#!/usr/bin/env python3

import hashlib
import fnmatch
import json
import logging
import os
import tempfile

from pathlib import Path

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.callbacks.base import BaseCallbackHandler
from langchain_litellm import ChatLiteLLM
from langchain.schema import LLMResult, AgentAction, AgentFinish
from langchain.tools import BaseTool, tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import Runnable
from litellm import cost_per_token, RateLimitError
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from typing import Any, Dict, Type, Union
from pydantic import BaseModel, Field, field_validator

from .beepobjs import BeepSeed
from .cpmeta import CPMetadata
from .fuzzer.jazzer import JazzerFuzzer
from .utils import CRS_ERR_LOG, CRS_WARN_LOG, get_with_model_provider

CRS_ERR = CRS_ERR_LOG("agent")
CRS_WARN = CRS_WARN_LOG("agent")
logger = logging.getLogger(__name__)
logging.getLogger("LiteLLM").setLevel(logging.INFO)

class HexStringInput(BaseModel):
    """Hex-encoded string input."""
    data: str = Field(description="The hex encoded input (e.g., '48656c6c6f')")


class BytesInput(BaseModel):
    """Direct bytes array input."""
    data: bytes = Field(description="The raw bytes input (not hex encoded)")


class PythonScriptInput(BaseModel):
    """Python script that generates input."""
    code: str = Field(description="Python code that returns bytes when executed, can only contain ASCII-printable characters; last instruction or 'result' variable is returned")

    @field_validator('code')
    def validate_code(cls, v):
        # Ensure it's all ASCII and no null or control characters
        if not all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in v):
            raise ValueError("Code must be ASCII and cannot contain null or control characters")
        return v

class FlexibleInput(BaseModel):
    """Flexible input schema supporting multiple input types using Union."""
    input_data: Union[HexStringInput, BytesInput, PythonScriptInput] = Field(
        description="Input data in one of the supported formats"
    )

    def to_bytes(self) -> bytes:
        """Convert the input to bytes regardless of the input type."""
        if isinstance(self.input_data, HexStringInput):
            try:
                return bytes.fromhex(self.input_data.data)
            except ValueError as e:
                raise ValueError(f"Invalid hex input: {e}")
        elif isinstance(self.input_data, BytesInput):
            return self.input_data.data
        elif isinstance(self.input_data, PythonScriptInput):
            try:
                # Execute the Python script in a restricted environment
                local_vars = {}
                global_vars = {
                    "__builtins__": {
                        "bytearray": bytearray,
                        "bytes": bytes,
                        "int": int,
                        "str": str,
                        "list": list,
                        "tuple": tuple,
                        "dict": dict,
                        "range": range,
                        "len": len,
                        "sum": sum,
                        "min": min,
                        "max": max,
                        "abs": abs,
                        "pow": pow,
                        "round": round,
                        "enumerate": enumerate,
                        "zip": zip,
                        "map": map,
                        "filter": filter,
                        "True": True,
                        "False": False,
                        "type": type,
                        "None": None,
                        "__import__": __import__,
                    }
                }

                exec(self.input_data.code, global_vars, local_vars)

                # Look for a result variable or the last expression
                if 'result' in local_vars:
                    result = local_vars['result']
                else:
                    result = list(local_vars.values())[-1] if local_vars else None

                if isinstance(result, bytes):
                    return result
                elif isinstance(result, str):
                    return bytes.fromhex(result)
                else:
                    try:
                        # Try to convert anything else to bytes
                        return bytes(result)
                    except Exception:
                        raise ValueError(f"Script must return bytes, str (hex), or something convertible to bytes, got {type(result)}")
            except Exception as e:
                raise ValueError(f"Error executing Python script: {e}")
        else:
            raise ValueError(f"Unsupported input type: {self.input_data.type}")


class JdbToolInput(BaseModel):
    """Input schema for JDB tool."""
    input_data: Union[HexStringInput, BytesInput, PythonScriptInput] = Field(
        description="Input data in one of the supported formats"
    )
    break_class: str = Field(description="The class where to set the breakpoint")
    break_line: int = Field(description="The line number where to set the breakpoint")
    commands: str = Field(description="A list of jdb commands to execute after hitting the breakpoint")


@tool(args_schema=JdbToolInput)
def jdb_tool(input_data: Union[HexStringInput, BytesInput, PythonScriptInput],
             break_class: str, break_line: int, commands: str) -> str:
    """A tool to interact with the Java Debugger (jdb).

    Args:
        input_data: The input data in one of the supported formats
        break_class: The class where to set the breakpoint
        break_line: The line number where to set the breakpoint
        commands: A list of jdb commands to execute after hitting the breakpoint

    Returns:
        The output from the jdb session
    """
    try:
        flexible_input = FlexibleInput(input_data=input_data)
        input_bytes = flexible_input.to_bytes()
        hex_input = input_bytes.hex()
        # TODO(fab1ano): implement actual JDB functionality using hex_input
        return f"jdb tool not implemented yet (would use hex input: {hex_input})"
    except Exception as e:
        return f"Error processing input: {e}"


class GenericPoVVerifier:
    """Generic PoV verifier using Jazzer."""
    jazzer_base: JazzerFuzzer = None
    counter: int = 0
    first_solved: int = None
    beepseed: BeepSeed = None
    last_input: bytes = None
    work_dir: Path = None

    def __init__(self, jazzer: JazzerFuzzer, beepseed: BeepSeed, work_dir: Path):
        super().__init__()
        self.jazzer_base = jazzer
        self.beepseed = beepseed
        self.work_dir = work_dir

    def check_crashes(self, input_data: Union[HexStringInput, BytesInput, PythonScriptInput]) -> str:
        """A tool to check if a PoV exploits the vulnerability.

        Args:
            input_data: The input data in one of the supported formats

        Returns:
            The result of the verification
        """
        self.counter += 1
        logger.info(f"Verifying input (attempt {self.counter})")

        try:
            flexible_input = FlexibleInput(input_data=input_data)
            input_bytes = flexible_input.to_bytes()
        except Exception as e:
            logger.error(f"Error processing input (attempt {self.counter}): {e}")
            return f"Error processing input (attempt {self.counter}): {e}"

        self.last_input = input_bytes

        crashes = self._get_crash_for_input(input_bytes)
        logger.info(f"found crashes: {crashes}")
        crash_found = any([self._check_crash(crash) for crash in crashes])

        if crash_found:
            logger.info(f"Crash found in verifier (attempt {self.counter})!")
            if self.first_solved is None:
                self.first_solved = self.counter
            return f"Exploit successful, crash found"
        else:
            logger.info(f"No crashes found in verifier (attempt {self.counter})")
            return "No crashes found, exploit unsuccessful"  # TODO(fab1ano): add info whether sinkpoint was reached

    def _check_crash(self, crash: Any) -> bool:
        """Check if the given crash matches the expected vulnerability.

        Args:
            crash: The crash data to check

        Returns:
            True if the crash matches the expected vulnerability, False otherwise
        """
        stack_trace = crash[3]
        for stack_frame in stack_trace:
            class_name = self.beepseed.coord.class_name.replace("/", ".")
            method_name = self.beepseed.coord.method_name
            line_no = self.beepseed.coord.line_num
            file_name = self.beepseed.coord.file_name
            signature = f"{class_name}.{method_name}({file_name}:{line_no})"
            if signature in stack_frame:
                return True

        return False

    def _get_crash_for_input(self, input_bytes: bytes) -> list[Any]:
        """Run jazzer with the given input and check for crashes.

        Args:
            input_bytes: The input bytes to be used as PoV

        Returns:
            A list of crashes found, empty if none
        """

        # Define the run_id
        input_hash = hashlib.sha256(input_bytes).hexdigest()
        input_id = f"verify-{input_hash}"
        run_id = f"id-{input_hash}"

        self.jazzer_base.add_corpus_file(input_bytes, input_id)

        with tempfile.TemporaryDirectory() as work_dir:
            logger.info(f"Running verification in {work_dir}")
            jazzer = self.jazzer_base.clone(work_dir=Path(work_dir))
            input_file = jazzer.add_corpus_file(input_bytes, "poc")
            result_json = jazzer.fuzz(run_id, 60, verify_only=True)
            logger.info("Finished jazzer run, checking results")

            fuzz_log_file = jazzer.fuzz_log
            if fuzz_log_file.exists():
                # Save the fuzz log for debugging
                saved_log = self.work_dir / f"verify-fuzz-{self.counter}.log"
                with open(fuzz_log_file, "r") as src, open(saved_log, "w") as dst:
                    dst.write(src.read())
                logger.info(f"Saved fuzz log to {saved_log}")

                # Check for "Executed <input_file>" in the log
                with open(fuzz_log_file, "r") as f:
                    log_content = f.read()
                    if f"Executed {input_file}" not in log_content:
                        logger.warning(f"{CRS_ERR} Input file {input_file} was not executed during verification!")
                        if "ERROR: libFuzzer: timeout after " in log_content:
                            logger.warning(f"{CRS_ERR} Verification run timed out")
                            return []
                        else:
                            raise RuntimeError(f"Input file {input_file} was not executed during verification!")
            else:
                logger.warning(f"{CRS_ERR} Fuzz log file {fuzz_log_file} does not exist!")
                raise RuntimeError(f"Fuzz log file {fuzz_log_file} does not exist!")

            if result_json.exists():
                with open(result_json, "r") as f:
                    result = json.load(f)
                    # Check if there's an entry in result["fuzz_data"]["log_dedup_crash_over_time"]
                    # TODO(fab1ano): improve crash detection logic
                    if "fuzz_data" in result and "log_dedup_crash_over_time" in result["fuzz_data"]:
                        crashes = result["fuzz_data"]["log_dedup_crash_over_time"]
                        if crashes:
                            logger.info("Crash found in verifier!")
                            return crashes

        logger.info("No crashes found in verifier.")
        return []


class VerificationTool(BaseTool):
    """A tool to verify if a PoV exploits the vulnerability."""
    name: str = "verify_exploit"
    description: str = ("A tool to check if a PoV exploits the vulnerability. "
                        "It takes as input a PoV "
                        "and returns whether it successfully triggers the vulnerability "
                        "by running it against the target Java program using Jazzer.")
    verifier: GenericPoVVerifier = None

    def __init__(self, verifier: GenericPoVVerifier):
        super().__init__()
        self.verifier = verifier


class HexStringVerificationTool(VerificationTool):
    """PoV checker tool specialized for hex string input."""
    name: str = "verify_exploit_hex"
    args_schema: Type[BaseModel] = HexStringInput

    def __init__(self, verifier: GenericPoVVerifier):
        super().__init__(verifier)

    def _run(self, data: str) -> str:
        return self.verifier.check_crashes(HexStringInput(data=data))


class BytesVerificationTool(VerificationTool):
    """PoV checker tool specialized for bytes array input."""
    name: str = "verify_exploit_bytes"
    args_schema: Type[BaseModel] = BytesInput

    def __init__(self, verifier: GenericPoVVerifier):
        super().__init__(verifier)

    def _run(self, data: bytes) -> str:
        return self.verifier.check_crashes(BytesInput(data=data))


class ScriptVerificationTool(VerificationTool):
    """PoV checker tool specialized for Python script input."""
    name: str = "verify_exploit_script"
    args_schema: Type[BaseModel] = PythonScriptInput

    def __init__(self, verifier: GenericPoVVerifier):
        super().__init__(verifier)

    def _run(self, code: str) -> str:
        return self.verifier.check_crashes(PythonScriptInput(code=code))


class FilePathInput(BaseModel):
    """Input schema for file path."""
    file_path: str = Field(description="Path to the file to read (absolute or relative)")


class UnifiedReadFileTool(BaseTool):
    """Unified read file tool that checks both root directories."""
    name: str = "read_file"
    description: str = "Read a file from either the OSS-Fuzz project directory or the challenge project source code. Provide either an absolute path or a relative path (will check both roots)."
    args_schema: Type[BaseModel] = FilePathInput

    ossfuzz_root: str = None
    source_root: str = None

    def __init__(self, ossfuzz_root: str = None, source_root: str = None):
        super().__init__()
        self.ossfuzz_root = ossfuzz_root
        self.source_root = source_root

    def _run(self, file_path: str) -> str:
        """Read file from one of the configured roots."""

        path = Path(file_path)

        # If absolute path, check if it's within one of the roots
        if path.is_absolute():
            if self.ossfuzz_root and path.is_relative_to(self.ossfuzz_root):
                if path.exists() and path.is_file():
                    return path.read_text()
                else:
                    return f"Error: File not found: {file_path}"
            elif self.source_root and path.is_relative_to(self.source_root):
                if path.exists() and path.is_file():
                    return path.read_text()
                else:
                    return f"Error: File not found: {file_path}"
            else:
                return f"Error: Path {file_path} is not within allowed directories ({self.ossfuzz_root}, {self.source_root})"

        # If relative path, try both roots
        else:
            if self.ossfuzz_root:
                ossfuzz_path = Path(self.ossfuzz_root) / file_path
                if ossfuzz_path.exists() and ossfuzz_path.is_file():
                    return ossfuzz_path.read_text()

            if self.source_root:
                source_path = Path(self.source_root) / file_path
                if source_path.exists() and source_path.is_file():
                    return source_path.read_text()

            return f"Error: File not found in any configured directory: {file_path}"


class DirectoryPathInput(BaseModel):
    """Input schema for directory path."""
    dir_path: str = Field(description="Path to the directory to list (absolute or relative)")


class UnifiedListDirectoryTool(BaseTool):
    """Unified list directory tool that checks both root directories."""
    name: str = "list_directory"
    description: str = "List contents of a directory from either the OSS-Fuzz project directory or the challenge project source code. Provide either an absolute path or a relative path (will check both roots)."
    args_schema: Type[BaseModel] = DirectoryPathInput

    ossfuzz_root: str = None
    source_root: str = None

    def __init__(self, ossfuzz_root: str = None, source_root: str = None):
        super().__init__()
        self.ossfuzz_root = ossfuzz_root
        self.source_root = source_root

    def _run(self, dir_path: str) -> str:
        """List directory contents from one of the configured roots."""

        path = Path(dir_path)

        # If absolute path, check if it's within one of the roots
        if path.is_absolute():
            if self.ossfuzz_root and path.is_relative_to(self.ossfuzz_root):
                if path.exists() and path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in path.iterdir()]
                    return "\n".join(sorted(items))
                else:
                    return f"Error: Directory not found: {dir_path}"
            elif self.source_root and path.is_relative_to(self.source_root):
                if path.exists() and path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in path.iterdir()]
                    return "\n".join(sorted(items))
                else:
                    return f"Error: Directory not found: {dir_path}"
            else:
                return f"Error: Path {dir_path} is not within allowed directories ({self.ossfuzz_root}, {self.source_root})"

        # If relative path, try both roots
        else:
            if self.ossfuzz_root:
                ossfuzz_path = Path(self.ossfuzz_root) / dir_path
                if ossfuzz_path.exists() and ossfuzz_path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in ossfuzz_path.iterdir()]
                    return "\n".join(sorted(items))

            if self.source_root:
                source_path = Path(self.source_root) / dir_path
                if source_path.exists() and source_path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in source_path.iterdir()]
                    return "\n".join(sorted(items))

            return f"Error: Directory not found in any configured directory: {dir_path}"


class SearchPatternInput(BaseModel):
    """Input schema for search pattern."""
    pattern: str = Field(description="File name pattern to search for (e.g., '*.java', 'Main.java')")


class UnifiedFileSearchTool(BaseTool):
    """Unified file search tool that searches in both root directories."""
    name: str = "search_files"
    description: str = "Search for files by name pattern in both the OSS-Fuzz project directory and the challenge project source code. Provide a search pattern (uses fnmatch; supports wildcards like *.java)."
    args_schema: Type[BaseModel] = SearchPatternInput

    ossfuzz_root: str = None
    source_root: str = None

    def __init__(self, ossfuzz_root: str = None, source_root: str = None):
        super().__init__()
        self.ossfuzz_root = ossfuzz_root
        self.source_root = source_root

    def _run(self, pattern: str) -> str:
        """Search for files matching pattern in configured roots."""

        results = []

        def search_in_directory(root: Path, pattern: str):
            matches = []
            for path in root.rglob('*'):
                if path.is_file() and (fnmatch.fnmatch(str(path), pattern) or
                                       fnmatch.fnmatch(path.name, pattern)):
                    matches.append(str(path))
            return matches

        if self.ossfuzz_root:
            ossfuzz_results = search_in_directory(Path(self.ossfuzz_root), pattern)
            results.extend(ossfuzz_results)

        if self.source_root:
            source_results = search_in_directory(Path(self.source_root), pattern)
            results.extend(source_results)

        if results:
            return "\n".join(sorted(results))
        else:
            return f"No files found matching pattern: {pattern}"


class LiteLLMCostTracker(BaseCallbackHandler):
    """Custom callback handler to track exact costs from LiteLLM server."""
    model: str

    def __init__(self, model: str):
        super().__init__()
        self.model = model
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.llm_calls = []

    def on_llm_end(
        self,
        response: LLMResult,
        **kwargs: Any,
    ) -> None:
        """Calculate cost when LLM call completes."""

        input_tokens = 0
        output_tokens = 0

        for gens in response.generations:
            for gen in gens:
                if gen.message.usage_metadata:
                    meta = gen.message.usage_metadata
                    input_tokens += meta.get('input_tokens', 0)
                    output_tokens += meta.get('output_tokens', 0)

        try:
            prompt_cost, completion_cost = cost_per_token(self.model, input_tokens, output_tokens)
        except Exception as e:
            logger.warning(f"Error calculating cost for model {self.model}, trying with provider: {e}")
            model_with_provider = get_with_model_provider(self.model)
            try:
                prompt_cost, completion_cost = cost_per_token(model_with_provider, input_tokens, output_tokens)
            except Exception as e2:
                logger.error(f"Failed to calculate cost with provider for model {model_with_provider}: {e2}")
                prompt_cost, completion_cost = 0.0, 0.0  # Fallback to zero cost if we can't calculate

        # Update totals
        self.total_cost += prompt_cost + completion_cost
        self.total_tokens += input_tokens + output_tokens
        self.total_prompt_tokens += input_tokens
        self.total_completion_tokens += output_tokens

        # Store call details
        call_info = {
            "model": self.model,
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cost": prompt_cost + completion_cost,
        }
        self.llm_calls.append(call_info)

    def get_summary(self) -> Dict[str, Any]:
        """Get cost tracking summary."""
        return {
            "total_cost": round(self.total_cost, 6),
            "total_tokens": self.total_tokens,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "num_llm_calls": len(self.llm_calls),
            "cost_breakdown": self.llm_calls
        }

    def reset(self):
        """Reset the cost tracker."""
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.llm_calls = []


class ExpkitExecutionContext:
    """Custom AgentExecutor for exploit generation and verification."""
    llm: ChatLiteLLM
    cost_tracker: LiteLLMCostTracker
    tools: list[BaseTool]
    agent: Runnable
    agent_executor: AgentExecutor
    verifier: GenericPoVVerifier
    work_dir: Path = None
    prompt: ChatPromptTemplate = None

    def __init__(
        self,
        model: str,
        temperature: float,
        jazzer: JazzerFuzzer,
        beepseed: BeepSeed,
        work_dir: Path,
        output_formats: list[str] = None,
        cp_meta: CPMetadata = None,
        max_iterations: int = 30,
        force_submission_threshold: float = 0.8
    ):
        api_key = os.environ.get("LITELLM_KEY")
        base_url = os.environ.get("AIXCC_LITELLM_HOSTNAME")

        self.work_dir = work_dir

        self.cost_tracker = LiteLLMCostTracker(model)

        # Initialize the language model
        self.llm = ChatLiteLLM(
            model=f"litellm_proxy/{model}",
            api_key=api_key,
            api_base=base_url,
            temperature=temperature,
            callbacks=[self.cost_tracker],
            request_timeout=240
        )
        self.llm.streaming = False  # Disable streaming for tool calling

        # Initialize the verifier
        self.verifier = GenericPoVVerifier(jazzer, beepseed, work_dir)

        # Default to all formats if not specified
        if output_formats is None:
            output_formats = ["hexstring", "bytes", "script"]

        # Normalize format names to lowercase
        output_formats = [fmt.lower() for fmt in output_formats]

        # Create the tools list based on selected formats
        verification_tools = []

        if "hexstring" in output_formats:
            verification_tools.append(HexStringVerificationTool(self.verifier))

        if "bytes" in output_formats:
            verification_tools.append(BytesVerificationTool(self.verifier))

        if "script" in output_formats:
            verification_tools.append(ScriptVerificationTool(self.verifier))

        # Add code exploration tools if cp_meta is provided
        code_exploration_tools = []
        if cp_meta is not None:
            # Get both root paths
            ossfuzz_root = str(cp_meta.get_proj_path()) if cp_meta.get_proj_path() else None
            source_root = str(cp_meta.get_repo_src_path()) if cp_meta.get_repo_src_path() else None

            # Create unified tools that work with both roots
            if ossfuzz_root or source_root:
                read_tool = UnifiedReadFileTool(
                    ossfuzz_root=ossfuzz_root,
                    source_root=source_root
                )
                code_exploration_tools.append(read_tool)

                list_tool = UnifiedListDirectoryTool(
                    ossfuzz_root=ossfuzz_root,
                    source_root=source_root
                )
                code_exploration_tools.append(list_tool)

                search_tool = UnifiedFileSearchTool(
                    ossfuzz_root=ossfuzz_root,
                    source_root=source_root
                )
                code_exploration_tools.append(search_tool)

                logger.info(f"Added unified file access tools with roots: ossfuzz={ossfuzz_root}, source={source_root}")
            else:
                logger.warning(f"{CRS_WARN} Could not determine source roots from cp_meta, code exploration tools not added")

        self.tools = verification_tools + code_exploration_tools

        # Create the prompt template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an expert Java security researcher and exploit developer. "
                      "The user provides you with details about a vulnerability in a Java program "
                      "and an input that reaches the sinkpoint of the vulnerability. "
                      "It is your task to use the given information and the tools to develop a working exploit. "
                      "Be precise and technical in your analyses and when creating the PoV. "
                      "Make sure to use the verification tool to check if your PoV works. "),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        # Create the agent
        self.agent = create_tool_calling_agent(self.llm, self.tools, self.prompt)

        # Create the agent executor
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=False,  # Set to True to see the agent's thought process
            handle_parsing_errors=True,
            return_intermediate_steps=True,
            max_iterations=max_iterations,  # Limit iterations to prevent infinite loops
        )

    @retry(
        wait=wait_exponential(multiplier=1, min=4, max=60),
        stop=stop_after_attempt(10),
        retry=retry_if_exception_type(RateLimitError)
    )
    def run(self, query: str) -> Dict:
        return self.agent_executor.invoke({"input": query})

    def solution(self) -> str | None:
        """Get the last solution in hex format, or None if not set."""
        return self.verifier.last_input.hex().lower() if self.verifier.last_input else None

    def tool_call_solved(self) -> int:
        return self.verifier.first_solved

    def get_cost_summary(self) -> str:
        summary = self.cost_tracker.get_summary()
        return (f"Total Cost: ${summary['total_cost']}, "
                f"Total Tokens: {summary['total_tokens']} "
                f"(Prompt: {summary['total_prompt_tokens']}, "
                f"Completion: {summary['total_completion_tokens']}), "
                f"LLM Calls: {summary['num_llm_calls']}")

    def get_cost_summary_verbose(self) -> str:
        summary = self.cost_tracker.get_summary()
        lines = [
            "\n=== Cost Summary ===",
            f"Total Cost: ${summary['total_cost']}",
            f"Total Tokens: {summary['total_tokens']}",
            f" - Prompt Tokens: {summary['total_prompt_tokens']}",
            f" - Completion Tokens: {summary['total_completion_tokens']}",
            f"Number of LLM Calls: {summary['num_llm_calls']}",
            "Cost Breakdown per Call:"
        ]
        for call in summary['cost_breakdown']:
            lines.append(
                f"Prompt Tokens: {call['prompt_tokens']}, "
                f"Completion Tokens: {call['completion_tokens']}, "
                f"Total Tokens: {call['total_tokens']}, "
                f"Cost: ${call['cost']}"
            )
        lines.append("====================\n")
        return "\n".join(lines)
