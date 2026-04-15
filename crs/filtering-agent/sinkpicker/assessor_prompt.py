#!/usr/bin/env python3

import logging
from pathlib import Path

from .cpmeta import CPMetadata
from .utils import CRS_ERR_LOG, CRS_WARN_LOG

logger = logging.getLogger(__name__)

CRS_ERR = CRS_ERR_LOG("exploitability_prompt")
CRS_WARN = CRS_WARN_LOG("exploitability_prompt")


class ExploitabilityPromptGenerator:
    """Generates prompts for the exploitability assessment agent."""

    # CWE descriptions for context
    CWE_DESCRIPTIONS = {
        "CWE-022": {
            "name": "Path Traversal",
            "description": "The software uses external input to construct a pathname that is intended to identify a file or directory located underneath a restricted parent directory, but does not properly neutralize special elements within the pathname that can cause it to resolve to a location outside of the restricted directory.",
            "exploitability_factors": [
                "Cache files/status files are considered safe",
                "Java class/project resources are considered safe",
                "Files with a static final path are considered safe",
                "If there are functions to normalize paths, check if there is any way around them; try to think of ways to bypass normalization",
                "Configuration values are considered safe",
                "When extracting files from an archive, it is exploitable if the file path is user-controlled (e.g., zip slip)",
                "If it's in a context where the user is intended to be able to provide any file it is also safe (not exploitable due to no threat model; e.g. cli arguments)",
                "It must be exploitable from the given harness; consider the context carefully"
            ]
        },
        "CWE-611": {
            "name": "XXE (XML External Entity)",
            "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
            "exploitability_factors": [
                "XML parser without external entity restrictions",
                "User-controlled XML input",
                "DTD processing enabled",
                "Public API that accepts XML data"
            ]
        },
        "CWE-643": {
            "name": "XPath Injection",
            "description": "The software uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input.",
            "exploitability_factors": [
                "User input directly concatenated into XPath queries",
                "Lack of parameterization or input validation",
                "XPath expressions used for authentication or authorization",
                "Public endpoints accepting XML queries"
            ]
        },
        "CWE-470": {
            "name": "Unsafe Reflection",
            "description": "The application uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.",
            "exploitability_factors": [
                "User-controlled class names or method names",
                "Reflection API usage (Class.forName, Method.invoke, etc.)",
                "Lack of whitelist for allowed classes/methods",
                "Public API endpoints that trigger reflection"
            ]
        },
        "CWE-730": {
            "name": "Regex Injection / ReDoS",
            "description": "The software uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive amounts of CPU cycles.",
            "exploitability_factors": [
                "User-controlled regex patterns",
                "Complex regex with nested quantifiers",
                "Pattern.compile with user input",
                "Public endpoints accepting regex patterns"
            ]
        },
        "CWE-089": {
            "name": "SQL Injection",
            "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
            "exploitability_factors": [
                "String concatenation for SQL queries",
                "Lack of parameterized queries or prepared statements",
                "User input in WHERE clauses, ORDER BY, or other SQL components",
                "Public API endpoints that interact with databases"
            ]
        },
        "CWE-090": {
            "name": "LDAP Injection",
            "description": "The software constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query.",
            "exploitability_factors": [
                "User input directly concatenated into LDAP queries",
                "Lack of input validation or escaping for LDAP special characters",
                "LDAP search filters constructed from user input",
                "Public API endpoints that perform LDAP queries"
            ]
        },
        "CWE-094": {
            "name": "Code Injection",
            "description": "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
            "exploitability_factors": [
                "User input passed to code evaluation functions (eval, script engines, expression language)",
                "Bean validation constraints with user-controlled expressions",
                "Template engines with user-controlled templates",
                "Dynamic code compilation or execution with user input",
                "Public API endpoints that process expressions or scripts"
            ]
        },
        "CWE-117": {
            "name": "Log Injection",
            "description": "The software does not neutralize or incorrectly neutralizes output that is written to logs. This allows an attacker to forge log entries or inject malicious content into logs.",
            "exploitability_factors": [
                "User input directly written to logs without sanitization",
                "Lack of encoding or escaping for log output",
                "Log entries that could be parsed by log analysis tools",
                "Potential for log forging or CRLF injection in logs",
                "Public endpoints where user input appears in logs"
            ]
        },
        "CWE-078": {
            "name": "OS Command Injection",
            "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
            "exploitability_factors": [
                "Input from the fuzzing harness passed to Runtime.exec or ProcessBuilder are often times exploitable",
                "Shell command construction via string concatenation",
                "If static final strings are used, it's likely safe; However, if command strings can be set at runtime, they may be exploitable",
                "Even just controling arguments is considered exploitable",
                "APIs for getting input/output streams, waiting for a process, or getting its exit value are safe; mark them as unexploitable",
                "Only mark as unexploitable if you are absolutely certain that this cannot be exploited; check the context carefully"
            ]
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
            "exploitability_factors": [
                "ObjectInputStream.readObject with untrusted data",
                "User-controlled serialized objects",
                "Lack of deserialization filters",
                "Public endpoints accepting serialized data"
            ]
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
            "exploitability_factors": [
                "User-controlled URLs in HTTP requests",
                "Internal network access from application with user-controlled input",
                "Accessing project resources is considered safe",
                "Closing a resource/disconnecting is never exploitable",
                "Just because a method is public does not make it exploitable; consider the context, there must be a clear threat given the harness"
            ]
        }
    }

    @staticmethod
    def get_cwe_description(cwe: str) -> str:
        """
        Get the formatted CWE description for a given CWE.

        Args:
            cwe: CWE identifier (e.g., "CWE-022")

        Returns:
            Formatted description string with name and description
        """
        cwe_info = ExploitabilityPromptGenerator.CWE_DESCRIPTIONS.get(cwe, {
            "name": cwe,
            "description": f"Vulnerability type {cwe}",
            "exploitability_factors": []
        })

        return f"""## Vulnerability Type
**{cwe}: {cwe_info['name']}**

{cwe_info['description']}"""

    @staticmethod
    def get_cwe_exploitability_factors(cwe: str) -> str:
        """
        Get the formatted exploitability factors for a given CWE.

        Args:
            cwe: CWE identifier (e.g., "CWE-022")

        Returns:
            Formatted exploitability factors as a bulleted list
        """
        cwe_info = ExploitabilityPromptGenerator.CWE_DESCRIPTIONS.get(cwe, {
            "name": cwe,
            "description": f"Vulnerability type {cwe}",
            "exploitability_factors": ["User-controlled input reaching the sink"]
        })

        factors_text = "\n".join([f"- {factor}" for factor in cwe_info["exploitability_factors"]])

        return f"""## Exploitability Factors to Consider
{factors_text}"""

    def __init__(self, cp_meta: CPMetadata, cwe: str, harness: str = None, call_graph = None):
        self.cp_meta = cp_meta
        self.cwe = cwe
        self.harness = harness
        self.call_graph = call_graph
        self.cwe_info = self.CWE_DESCRIPTIONS.get(cwe, {
            "name": cwe,
            "description": f"Vulnerability type {cwe}",
            "exploitability_factors": ["User-controlled input reaching the sink"]
        })

    def _read_harness_file(self, harness_name: str) -> str:
        """
        Read the harness file from the oss-fuzz directory.

        Args:
            harness_name: Name of the harness (e.g., "JenkinsOne")

        Returns:
            Contents of the harness file, or None if not found
        """
        harness_filename = f"{harness_name}.java"

        # Try to find the harness file in the oss-fuzz project directory
        proj_path = self.cp_meta.get_proj_path()
        if not proj_path:
            logger.warning(f"{CRS_WARN} Project path not available in metadata")
            return None

        # Search for the harness file
        proj_path_obj = Path(proj_path)

        # Try common locations
        search_paths = [
            proj_path_obj / harness_filename,  # Root of oss-fuzz project
            proj_path_obj / "src" / harness_filename,
            proj_path_obj / "src" / "main" / "java" / harness_filename,
        ]

        # Also search recursively in the project directory
        try:
            for candidate in proj_path_obj.rglob(harness_filename):
                if candidate.is_file():
                    logger.info(f"Found harness file: {candidate}")
                    with open(candidate, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
        except Exception as e:
            logger.warning(f"{CRS_WARN} Error searching for harness file: {e}")

        logger.warning(f"{CRS_WARN} Harness file not found: {harness_filename}")
        return None

    def _find_call_path(self, sink_file: str, sink_line: int) -> str:
        """
        Find a call path from fuzzerTestOneInput in the harness to the sink location.

        Args:
            sink_file: Sink file path
            sink_line: Sink line number

        Returns:
            Formatted call path string, or message if not found
        """
        if not self.call_graph or not self.harness:
            return "(call graph not available)"

        # Find the fuzzerTestOneInput method in the harness
        # The harness class is usually named after the harness file
        harness_class = self.harness  # May need adjustment based on package structure
        start_node = self.call_graph.find_node_by_method(harness_class, "fuzzerTestOneInput")

        if not start_node:
            logger.warning(f"{CRS_WARN} Could not find fuzzerTestOneInput in harness {self.harness}")
            return f"(fuzzerTestOneInput not found in call graph for harness {self.harness})"

        # Find the node containing the sink location
        end_node = self.call_graph.find_node_by_location(sink_file, sink_line)

        if not end_node:
            logger.warning(f"{CRS_WARN} Could not find sink location {sink_file}:{sink_line} in call graph")
            return f"(sink location {sink_file}:{sink_line} not found in call graph)"

        # Find path using BFS
        path = self.call_graph.find_path_bfs(start_node, end_node)

        if not path:
            logger.warning(f"{CRS_WARN} No call path found from {self.harness}.fuzzerTestOneInput to {sink_file}:{sink_line}")
            return f"(no call path found from fuzzerTestOneInput to sink)"

        # Format the path
        return self.call_graph.format_path(path)

    def _get_code_context(self, file_path: str, line_num: int, context_lines: int = 2) -> str:
        """
        Get code context around a specific line.

        Args:
            file_path: Path to the source file
            line_num: Line number to get context for (1-indexed)
            context_lines: Number of lines before and after to include

        Returns:
            Formatted code snippet with line numbers
        """
        # Try to find and read the file
        full_path = None

        # Check if it's an absolute path
        if Path(file_path).is_absolute():
            if Path(file_path).exists():
                full_path = Path(file_path)
        else:
            # Try relative to source root
            if self.cp_meta.get_repo_src_path():
                candidate = Path(self.cp_meta.get_repo_src_path()) / file_path
                if candidate.exists():
                    full_path = candidate

            # Try relative to project path
            if full_path is None and self.cp_meta.get_proj_path():
                candidate = Path(self.cp_meta.get_proj_path()) / file_path
                if candidate.exists():
                    full_path = candidate

        if full_path is None:
            return f"(Unable to read file: {file_path})"

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Calculate line range (convert to 0-indexed)
            start_line = max(0, line_num - 1 - context_lines)
            end_line = min(len(lines), line_num + context_lines)

            # Build formatted output
            result = []
            for i in range(start_line, end_line):
                line_content = lines[i].rstrip()
                # Mark the target line with an arrow
                if i == line_num - 1:
                    result.append(f"  > {i+1:4d} | {line_content}")
                else:
                    result.append(f"    {i+1:4d} | {line_content}")

            return "\n".join(result)

        except Exception as e:
            logger.warning(f"{CRS_WARN} Failed to read file {full_path}: {e}")
            return f"(Error reading file: {e})"

    def generate_exploitability_prompt(self, sink: dict) -> str:
        """
        Generate a prompt for the agent to assess exploitability of a single sink.

        Args:
            sink: Sink dictionary with 'id', 'coord', 'message', 'cwe', etc.

        Returns:
            A formatted prompt string
        """
        coord = sink["coord"]
        file_path = coord["file_name"]
        line_num = coord["line_num"]
        start_col = coord.get("start_column", "?")
        end_col = coord.get("end_column", "?")
        sink_id = sink["id"]
        message = sink.get("message", "")

        # Get code context
        code_context = self._get_code_context(file_path, line_num, context_lines=5)

        # Build exploitability factors
        factors_text = "\n".join([f"- {factor}" for factor in self.cwe_info["exploitability_factors"]])

        # Add harness information and file contents if available
        harness_section = ""
        if self.harness:
            # Try to find and read the harness file
            harness_file_content = self._read_harness_file(self.harness)

            if not harness_file_content:
                logger.error(f"{CRS_ERR} Harness file content not found for harness: {self.harness}")
                raise ValueError(f"Harness file content not found for harness: {self.harness}")

            # Find call path from fuzzerTestOneInput to sink
            call_path = self._find_call_path(file_path, line_num)

            harness_section = f"""
## Test Harness
This sink is associated with the test harness: **{self.harness}**

**Harness File: {self.harness}.java**
```java
{harness_file_content}
```

**One possible Call Path from fuzzerTestOneInput to Sink:**
```
{call_path}
```

Consider the harness context when assessing exploitability. The harness provides insights into:
- What functionality is being tested
- Potential entry points or attack surfaces
- How user input flows into the sink: Only input provided to fuzzerTestOneInput is considered attacker-controlled.
- The call path shows how execution may flow from the harness entry point to this sink

"""

        prompt = f"""# Exploitability Assessment Task

## Vulnerability Type
**{self.cwe}: {self.cwe_info['name']}**

{self.cwe_info['description']}
{harness_section}
## Exploitability Factors to Consider
{factors_text}

## Your Task
You are assessing the exploitability of a specific vulnerability sink point.

**Sink Information:**
- **ID:** `{sink_id}`
- **File:** `{file_path}`
- **Location:** Line {line_num}, columns {start_col}-{end_col}
- **Description:** {message}

**Code Context (±5 lines):**
```
{code_context}
```

## Instructions

1. **Analyze this specific sink** by considering:
   - Can user/external input reach this sink point? (trace back data flow)
   - What is the potential impact if exploited?
   - Are there any mitigating factors (security managers, sandboxing, etc.)?

2. **Make an exploitability assessment**:
   - Set `unexploitable=True` if the sink is unlikely to be exploitable
   - Set `unexploitable=False` if the sink is likely exploitable

3. **Provide a report**:
   - Justify your assessment with clear reasoning
   - Reference specific code lines or logic that influenced your decision

## Assessment Criteria

**Mark as unexploitable=True (NOT exploitable) if:**
- External input does not reach the sink point
- Input validation/sanitization is present and effective
- Security controls prevent exploitation
- You are certain that exploitation is not feasible

**Mark as unexploitable=False (potentially exploitable) if:**
- External input can reach the sink point
- Missing or incomplete input validation
- No effective security controls are in place

## Important Notes
- Code context (±5 lines) is provided to help with assessment
- Focus on practical exploitability, not just theoretical vulnerability
- Use the tools available to explore the codebase if you need more context
- Mark a location as exploitable if it is likely exploitable from the given harness
- Only check if the very specific line is vulnerable; we will handle other lines separately

Begin your assessment now.
"""
        return prompt
