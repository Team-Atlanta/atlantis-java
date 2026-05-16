#!/usr/bin/env python3

import logging
import os
from pathlib import Path

from hexdump2 import hexdump

from ..beepobjs import BeepSeed
from ..cpmeta import CPMetadata
from ..utils import CRS_ERR_LOG, CRS_WARN_LOG
from .pyshellcmd import cat_n, cat_n_at_line

logger = logging.getLogger(__name__)


CRS_ERR = CRS_ERR_LOG("prompt")
CRS_WARN = CRS_WARN_LOG("prompt")


class PromptGenerator:
    # TODO: refine this with adapted descriptions
    VULN_DESC_MAP = {
        "sink-ExpressionLanguageInjection": """
The code is potentially vulnerable to Expression Language Injection. Inputs that cause the expression language interpreter initializing/accessing class 'jaz.Zer' during execution will be detected by Jazzer as valid proof of concept.
- One typical payload is "\\${Byte.class.forName(\"jaz.Zer\").getMethod(\"el\").invoke(null)}"
""",
        "sink-LdapInjection": """
The code is potentially vulnerable to LDAP Injection. Inputs that lead to invalid LDAP search queries and trigger the following exception during execution will be detected by Jazzer as valid proof of concept.
- 1) javax.naming.directory.InvalidSearchFilterException
    + "\\+<>,;\"=" are helpful characters to escape in DNs
- 2) javax.naming.NamingException
    + "*()\\\u0000" are helpful characters to escape in search filter queries
""",
        "sink-LoadArbitraryLibrary": """
The code is potentially vulnerable to Load Arbitrary Library. Inputs that cause the library name argument equal to 'jazzer_honeypot' during execution will be detected by Jazzer as valid proof of concept.
""",
        "sink-OsCommandInjection": """
The code is potentially vulnerable to OS Command Injection. Inputs that can invoke command 'jazze' during execution will be detected by Jazzer as valid proof of concept.
""",
        "sink-RegexInjection": """
The code is potentially vulnerable to Regex Injection. Inputs that satisfying the following scenarios during execution will be detected by Jazzer as valid proof of concept.
- 1) triggering java.util.regex.PatternSyntaxException (NOT by stack overflow during pattern compilation)
    + "\\E]\\E]]]]]]" may be useful for this scenario
- 2) containing "\u0300\u0300\u0300" if API is java.util.regex.Pattern.compile(String regex, int flags) with CANON_EQ (canonical equivalence) flag enabled
""",
        "sink-RemoteJNDILookup": """
The code is potentially vulnerable to Remote JNDI Lookup. Inputs that retrieve the object starting with 'ldap://g.co/' or 'rmi://g.co/' during execution will be detected by Jazzer as valid proof of concept.
""",
        # TODO: the url mentioned may be non-deterministic for target harness
        "sink-UnsafeDeserialization": """
The code is potentially vulnerable to Unsafe Deserialization. Inputs that cause the execution to trigger any Jazzer sanitizer hooked functions will be detected as valid proof of concept. This includes scenarios such as initializing a class 'jaz.Zer', invoking a system command called 'jazze', or accessing any external URL (such as websites or host/IP:port combinations).
""",
        # TODO: check if more guidance on complicate payload is needed
        "sink-UnsafeReflectiveCall": """
The code is potentially vulnerable to Unsafe Reflective Call. Inputs that cause the execution to trigger any Jazzer sanitizer hooked functions will be detected as valid proof of concept.
- Typically, it is detected by initializing class 'jaz.Zer' or accessing its methods.
- If the above case is impossible, input which eventually executes a system command called 'jazze' or access any external URL (such as websites or host/IP:port combinations) via calling Java methods will also be detected.
""",
        "sink-XPathInjection": """
The code is potentially vulnerable to XPath Injection. Inputs that lead to invalid XPath queries and trigger XPathExpressionException by javax.xml.transform.TransformerException during execution will be detected by Jazzer as valid proof of concept.
""",
        # TODO: the url mentioned may be non-deterministic for target harness
        "sink-ServerSideRequestForgery": """
The code is potentially vulnerable to Server Side Request Forgery (SSRF). Inputs that cause the execution to access any external URL, such as websites or host/IP:port combinations, will be detected by Jazzer as valid proof of concept.
""",
        # TODO: the pwd may be non-deterministic for target harness
        "sink-FilePathTraversal": """
The code is potentially vulnerable to File Path Traversal. Inputs that cause the execution to access a file named 'jazzer-traversal', either through a relative path, i.e., '../jazzer-traversal', or an absolute path, i.e., '/tmp/jazzer-traversal' in this case, will be detected by Jazzer as valid proof of concept."
""",
        "sink-SqlInjection": """
The code is potentially vulnerable to SQL Injection, inputs that create invalid SQL statements and trigger SQL_SYNTAX_ERROR_EXCEPTIONS during execution will be detected by Jazzer as valid proof of concept.
SQL_SYNTAX_ERROR_EXCEPTIONS:
  - java.sql.SQLException
  - java.sql.SQLNonTransientException
  - java.sql.SQLSyntaxErrorException
  - org.h2.jdbc.JdbcSQLSyntaxErrorException
  - org.h2.jdbc.JdbcSQLFeatureNotSupportedException
Common escape characters: "'", "\"", "\b", "\n", "\r", "\t", "\\", "%", "_"
""",
        "sink-BigDecimal": """
The code is potentially vulnerable to BigDecimal DoS. If the input can partially or fully control the first argument of the BigDecimal constructor, it can lead to a DoS condition by causing the BigDecimal object to take an excessive amount of time to parse or create. The key of launching such DoS is to provide a string that is either long enough in integral part or decimal parts, or both. The length depends on the case but should usually be 1K to 300K. If you are building the poc construction script, this can be easily controlled programmatically.
""",
        "sink-SAXParser": """
The code is potentially vulnerable if the first argument of SAXParser.parse can be controlled. In that case, it can lead to various consequences depending on the input and the XML content being parsed, such as File Path Traversal, Server Side Request Forgery (SSRF), Remote Code Execution (RCE), or Denial of Service (DoS) conditions (Billion Laughs Attack). There are several SAXPraser.parse functions accepting different types of first argument, like uri string, file, or inputsource/inputstream. If its content can be controlled, attackers need to manipulate that input to eventually lead the SAXParser to parse crafted XML which contains external entity references or other malicious content. In our context, the PoC needs to be able to trigger the Jazzer sanitizer hooked functions, such as initializing a class 'jaz.Zer', invoking a system command called 'jazze', or accessing any external URL (such as websites or host/IP:port combinations), accessing a file named 'jazzer-traversal', or causing a DoS condition by Billion Laughs Attack, etc.
""",
        "sink-batik-TranscoderInput": """
The code is potentially vulnerable if the first argument of TranscoderInput can be controlled. Typically, given one type of transcoder input, such as a svg file,the attacker can embed payload by crafting the external resource contained inside the svg, such as xlink:href or href in svg file. If the target program doesn't securely handle the embedded metadata, it can lead to various consequences depending on the input and the payload, such as File Path Traversal, Server Side Request Forgery (SSRF), Remote Code Execution (RCE), or Denial of Service (DoS) conditions. In our context, the PoC needs to be able to trigger the Jazzer sanitizer hooked functions, such as initializing a class 'jaz.Zer', invoking a system command called 'jazze', or accessing any external URL (such as websites or host/IP:port combinations), accessing a file named 'jazzer-traversal', or causing a timeout or OOM condition for DoS, etc.
""",
        "sink-ScriptEngineInjection": """
The code is potentially vulnerable to a script injection. Inputs that contain the string '"jaz"+"zer"' (including the double quotes) during execution will be detected by Jazzer as valid proof of concept.
""",
        "sink-RemoteCodeExecution": """
The code is potentially vulnerable to Remote Code Execution (RCE). This can happen when the code uses unsafe deserialization, unsafe reflection, or other mechanisms that allow for dynamic code execution. Inputs that cause the execution to trigger any Jazzer sanitizer hooked functions will be detected as valid proof of concept. This includes scenarios such as initializing a class 'jaz.Zer' and invoking a system command called 'jazze'.
""",
    }

    _poc_template = None
    _dict_template = None
    _script_template = None
    _extract_hexstr_template = None

    @classmethod
    def _load_template(cls, filename):
        """Load a template file from the prompts directory."""
        template_path = Path(os.path.dirname(__file__)) / "prompts" / filename
        with open(template_path) as f:
            return f.read()

    def __init__(self, cp_meta: CPMetadata, beepseed: BeepSeed, trim_context: bool = True):
        self.cp_meta = cp_meta
        self.cp_name = cp_meta.get_cp_name()
        self.beepseed = beepseed
        self.trim_context = trim_context

        if PromptGenerator._poc_template is None:
            PromptGenerator._poc_template = self._load_template("gen-poc.txt")
        if PromptGenerator._dict_template is None:
            PromptGenerator._dict_template = self._load_template("gen-dict.txt")
        if PromptGenerator._extract_hexstr_template is None:
            PromptGenerator._extract_hexstr_template = self._load_template(
                "x-hexstr.txt"
            )
        if PromptGenerator._script_template is None:
            PromptGenerator._script_template = self._load_template("gen-script.txt")

    def _get_file_content_with_context(self, file_path: str, line_numbers: list[int]) -> str:
        """
        Get file content - either full file or snippets around line numbers for large files.

        Args:
            file_path: Path to the source file
            line_numbers: Line numbers from stack trace frames

        Returns:
            Formatted file content with line numbers
        """
        # If trim_context is False, always return the full file
        if not self.trim_context:
            return cat_n(file_path)

        # Define line count threshold for when to use snippets
        LINE_COUNT_THRESHOLD = 150

        # Check line count
        try:
            with open(file_path) as f:
                line_count = sum(1 for _ in f)
        except (FileNotFoundError, OSError):
            line_count = 0

        if line_count < LINE_COUNT_THRESHOLD:
            # Small file: show entire content
            return cat_n(file_path)

        # Large file: show merged snippets around line numbers
        if not line_numbers:
            return cat_n(file_path)

        line_nums = sorted(line_numbers)

        # Merge overlapping or nearby ranges (within 10 lines)
        CONTEXT_LINES = 50
        MERGE_DISTANCE = CONTEXT_LINES * 2

        merged_ranges = []
        for line_num in line_nums:
            start = max(1, line_num - CONTEXT_LINES)
            end = line_num + CONTEXT_LINES

            # Check if this range overlaps or is close to the last merged range
            if merged_ranges and start <= merged_ranges[-1][1] + MERGE_DISTANCE:
                # Merge with previous range
                merged_ranges[-1] = (
                    merged_ranges[-1][0],
                    max(merged_ranges[-1][1], end),
                )
            else:
                # Add new range
                merged_ranges.append((start, end))

        # Read file content for the merged ranges
        snippets = []
        for start, end in merged_ranges:
            snippet = cat_n_at_line(
                file_path, (start + end) // 2, context_lines=(end - start) // 2
            )
            snippets.append(snippet)

        if snippets:
            return "\n...\n".join(snippets)
        else:
            return cat_n(file_path)

    def get_code_files(self) -> str:
        if not self.beepseed.stack_trace:
            return "No stack trace available to extract code files"

        # Find the stack frames that have CP project source files and collect line numbers
        file_line_ranges = {}  # file_path -> list of line numbers
        for frame in self.beepseed.stack_trace:
            source_path = self.cp_meta.resolve_frame_to_file_path(frame)
            if source_path:
                line_num = frame.get("line_num", -1)
                if line_num > 0:
                    if source_path not in file_line_ranges:
                        file_line_ranges[source_path] = []
                    file_line_ranges[source_path].append(line_num)

        if not file_line_ranges:
            return "No relevant source code files found in stack trace"

        formatted_files = []
        for file_path in sorted(file_line_ranges.keys()):
            file_header = f"// File: {file_path}"
            file_content = self._get_file_content_with_context(
                file_path, file_line_ranges[file_path]
            )

            formatted_file = f"```\n{file_header}\n{file_content}\n```"
            formatted_files.append(formatted_file)

        return "\n\n".join(formatted_files)

    def get_sinkpoint_file_path(self) -> str | None:
        class_name = self.beepseed.coord.class_name.replace("/", ".")
        file_name = self.beepseed.coord.file_name
        return self.cp_meta.resolve_file_path(class_name, file_name)

    def get_sinkpoint_lineno(self) -> str:
        return str(self.beepseed.coord.line_num or "?")

    def get_sinkpoint_line_content(self) -> str:
        file_path = self.get_sinkpoint_file_path()
        target_line = self.beepseed.coord.line_num

        if not file_path or not target_line:
            return "Unable to extract line content: file path or line number missing"

        return cat_n_at_line(file_path, target_line, context_lines=0)

    def get_sinkpoint_vuln_desc(self) -> str:
        mark_desc = self.beepseed.coord.mark_desc
        return self.VULN_DESC_MAP.get(
            mark_desc,
            # In case no match at all, but should not happen
            f"The code is potentially vulnerable to {mark_desc} vulnerability",
        )

    def get_beepseed_hexdump(self) -> str:
        """Generate a hexdump of the beepseed data in 'hexdump -C' format."""
        if not self.beepseed.data_hex_str:
            return "Zero-length data"

        try:
            data = bytes.fromhex(self.beepseed.data_hex_str)
        except ValueError:
            return f"Error: Invalid hex string: {self.beepseed.data_hex_str}"

        dump_str = hexdump(data, offset=0, collapse=True, color=False, result="return")
        if len(dump_str) > 4096:
            dump_str = dump_str[:4096] + "\n... (truncated for brevity)"
        return dump_str

    def get_beepseed_stacktrace(self) -> str:
        """Format stack trace from the beepseed."""
        if not self.beepseed.stack_trace:
            return "No stack trace available"

        filtered_frames = self.beepseed.filter_frames_from_codemarker()

        formatted_trace = "== Stacktrace when the given input reaches the sinkpoint:\n"
        for frame in filtered_frames:
            formatted_trace += f"        at {frame}\n"
        formatted_trace += "\n"

        return formatted_trace

    def generate_poc_prompt(self) -> str:
        prompt = self._poc_template

        replacements = {
            "PROMPT_CP_NAME": self.cp_name,
            "PROMPT_CODE_FILES": self.get_code_files(),
            "PROMPT_SINKPOINT_FILE_PATH": self.get_sinkpoint_file_path(),
            "PROMPT_SINKPOINT_LINENO": self.get_sinkpoint_lineno(),
            "PROMPT_SINKPOINT_LINE_CONTENT": self.get_sinkpoint_line_content(),
            "PROMPT_SINKPOINT_VULN_DESC": self.get_sinkpoint_vuln_desc(),
            "PROMPT_BEEPSEED_HEXDUMP": self.get_beepseed_hexdump(),
            "PROMPT_BEEPSEED_STACKTRACE": self.get_beepseed_stacktrace(),
        }

        for placeholder, value in replacements.items():
            if value is None:
                logger.warning(
                    f"{CRS_WARN} missing {placeholder} info for {self.beepseed}"
                )
                value = "N/A"
            prompt = prompt.replace(placeholder, str(value))

        return prompt

    def generate_poc_script(self) -> str:
        prompt = self._script_template

        replacements = {
            "PROMPT_CP_NAME": self.cp_name,
            "PROMPT_CODE_FILES": self.get_code_files(),
            "PROMPT_SINKPOINT_FILE_PATH": self.get_sinkpoint_file_path(),
            "PROMPT_SINKPOINT_LINENO": self.get_sinkpoint_lineno(),
            "PROMPT_SINKPOINT_LINE_CONTENT": self.get_sinkpoint_line_content(),
            "PROMPT_SINKPOINT_VULN_DESC": self.get_sinkpoint_vuln_desc(),
            "PROMPT_BEEPSEED_HEXDUMP": self.get_beepseed_hexdump(),
            "PROMPT_BEEPSEED_STACKTRACE": self.get_beepseed_stacktrace(),
        }

        for placeholder, value in replacements.items():
            if value is None:
                logger.warning(
                    f"{CRS_WARN} missing {placeholder} info for {self.beepseed}"
                )
                value = "N/A"
            prompt = prompt.replace(placeholder, str(value))
        return prompt

    def generate_dict_prompt(self) -> str:
        return self._dict_template

    def generate_x_hexstr_prompt(self, resp) -> str:
        prompt = self._extract_hexstr_template

        replacements = {
            "PROMPT_POC_GENERATION_RESP": resp,
        }

        for placeholder, value in replacements.items():
            prompt = prompt.replace(placeholder, value)

        return prompt
