#!/usr/bin/env python3

import fnmatch
import logging
import os
from pathlib import Path
from typing import Any, Dict, Type

from func_timeout import func_timeout, FunctionTimedOut
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.callbacks.base import BaseCallbackHandler
from langchain.schema import LLMResult
from langchain.tools import BaseTool
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate, MessagesPlaceholder
from langchain_litellm import ChatLiteLLM
from langgraph.graph import StateGraph, END
from litellm import cost_per_token, RateLimitError
from pydantic import BaseModel, Field
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential, before_sleep_log, after_log
from typing import Optional, TypedDict, Annotated, Sequence
import operator

from .cpmeta import CPMetadata
from .utils import CRS_ERR_LOG, CRS_WARN_LOG, get_with_model_provider
from .assessor_prompt import ExploitabilityPromptGenerator

CRS_ERR = CRS_ERR_LOG("exploitability_agent")
CRS_WARN = CRS_WARN_LOG("exploitability_agent")
logger = logging.getLogger(__name__)
logging.getLogger("LiteLLM").setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s")
logging.getLogger("LiteLLM").handlers[0].setFormatter(formatter)


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
        import html
        logger.info(f"[Tool] read_file START: {file_path}")

        path = Path(file_path)
        result = None

        def read_file_content(p: Path) -> str:
            logger.info(f"[Tool] read_file: Reading file {p}")
            result = p.read_text()

            return result

        # If absolute path, check if it's within one of the roots
        if path.is_absolute():
            if self.ossfuzz_root and path.is_relative_to(self.ossfuzz_root):
                if path.exists() and path.is_file():
                    result = read_file_content(path)
                else:
                    result = f"Error: File not found: {file_path}"
            elif self.source_root and path.is_relative_to(self.source_root):
                if path.exists() and path.is_file():
                    result = read_file_content(path)
                else:
                    result = f"Error: File not found: {file_path}"
            else:
                result = f"Error: Path {file_path} is not within allowed directories ({self.ossfuzz_root}, {self.source_root})"

        # If relative path, try both roots
        else:
            if self.ossfuzz_root:
                ossfuzz_path = Path(self.ossfuzz_root) / file_path
                if ossfuzz_path.exists() and ossfuzz_path.is_file():
                    result = read_file_content(ossfuzz_path)

            if result is None and self.source_root:
                source_path = Path(self.source_root) / file_path
                if source_path.exists() and source_path.is_file():
                    result = read_file_content(source_path)

            if result is None:
                result = f"Error: File not found in any configured directory: {file_path}"

        logger.info(f"[Tool] read_file END: {len(result)} chars")
        return result


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
        logger.info(f"[Tool] list_directory START: {dir_path}")

        path = Path(dir_path)

        result = None

        # If absolute path, check if it's within one of the roots
        if path.is_absolute():
            if self.ossfuzz_root and path.is_relative_to(self.ossfuzz_root):
                if path.exists() and path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in path.iterdir()]
                    result = "\n".join(sorted(items))
                else:
                    result = f"Error: Directory not found: {dir_path}"
            elif self.source_root and path.is_relative_to(self.source_root):
                if path.exists() and path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in path.iterdir()]
                    result = "\n".join(sorted(items))
                else:
                    result = f"Error: Directory not found: {dir_path}"
            else:
                result = f"Error: Path {dir_path} is not within allowed directories ({self.ossfuzz_root}, {self.source_root})"

        # If relative path, try both roots
        else:
            if self.ossfuzz_root:
                ossfuzz_path = Path(self.ossfuzz_root) / dir_path
                if ossfuzz_path.exists() and ossfuzz_path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in ossfuzz_path.iterdir()]
                    result = "\n".join(sorted(items))

            if result is None and self.source_root:
                source_path = Path(self.source_root) / dir_path
                if source_path.exists() and source_path.is_dir():
                    items = [item.name + "/" if item.is_dir() else item.name for item in source_path.iterdir()]
                    result = "\n".join(sorted(items))

            if result is None:
                result = f"Error: Directory not found in any configured directory: {dir_path}"

        logger.info(f"[Tool] list_directory END: {len(result)} chars")
        return result


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
        logger.info(f"[Tool] search_files START: {pattern}")

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
            result = "\n".join(sorted(results))
        else:
            result = f"No files found matching pattern: {pattern}"

        logger.info(f"[Tool] search_files END: {len(result)} chars, {len(results)} files")
        return result


class ExploitabilityAssessment(BaseModel):
    """Structured output schema for exploitability assessment."""
    unexploitable: bool = Field(
        description="True if the sink is NOT exploitable (well-protected), False if potentially exploitable"
    )
    reasoning: str = Field(
        description="Brief explanation of the exploitability assessment (2-3 sentences)"
    )


class AgentState(TypedDict):
    """State for the two-stage exploitability assessment agent."""
    # Input
    initial_prompt: str

    # Research phase
    research_notes: Annotated[list[str], operator.add]
    research_iterations: int
    used_fallback_report: bool

    # Assessment phase
    assessment: Optional[ExploitabilityAssessment]

    # Metadata
    intermediate_steps: Annotated[list, operator.add]


class LLMInteractionLogger(BaseCallbackHandler):
    """Captures every LLM prompt and response for debugging."""

    def __init__(self):
        super().__init__()
        self.interactions = []
        self._pending_prompts = {}  # run_id -> prompts

    def on_llm_start(self, serialized: Dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        run_id = kwargs.get("run_id", "unknown")
        self._pending_prompts[str(run_id)] = prompts

    def on_chat_model_start(self, serialized: Dict[str, Any], messages: list, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id", "unknown"))
        formatted = []
        for msg_group in messages:
            for msg in msg_group:
                role = getattr(msg, "type", "unknown")
                content = getattr(msg, "content", str(msg))
                tool_calls = getattr(msg, "tool_calls", None)
                entry = f"[{role}] {content}"
                if tool_calls:
                    entry += f"\n  tool_calls: {tool_calls}"
                formatted.append(entry)
        self._pending_prompts[run_id] = formatted

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id", "unknown"))
        prompts = self._pending_prompts.pop(run_id, ["(prompts not captured)"])

        response_texts = []
        for gens in response.generations:
            for gen in gens:
                text = getattr(gen, "text", "")
                msg = getattr(gen, "message", None)
                if msg:
                    content = getattr(msg, "content", "")
                    tool_calls = getattr(msg, "tool_calls", None)
                    if content:
                        response_texts.append(str(content))
                    if tool_calls:
                        response_texts.append(f"tool_calls: {tool_calls}")
                elif text:
                    response_texts.append(text)

        self.interactions.append({
            "prompts": prompts,
            "response": response_texts,
        })

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id", "unknown"))
        prompts = self._pending_prompts.pop(run_id, ["(prompts not captured)"])
        self.interactions.append({
            "prompts": prompts,
            "response": [f"ERROR: {error}"],
        })

    def dump(self, path: Path) -> None:
        """Write all interactions to a file."""
        with open(path, "w") as f:
            for i, interaction in enumerate(self.interactions, 1):
                f.write(f"{'='*80}\n")
                f.write(f"LLM CALL #{i}\n")
                f.write(f"{'='*80}\n\n")
                f.write("--- PROMPT ---\n\n")
                for prompt in interaction["prompts"]:
                    f.write(str(prompt))
                    f.write("\n\n")
                f.write("--- RESPONSE ---\n\n")
                for resp in interaction["response"]:
                    f.write(str(resp))
                    f.write("\n\n")


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


class ExploitabilityAssessor:
    """Two-stage LangGraph agent for exploitability assessment.

    Stage 1 (Research): Agent explores code with tools, gathering information
    Stage 2 (Assessment): Agent uses structured output to assess exploitability
    """
    llm: ChatLiteLLM
    llm_with_structure: ChatLiteLLM
    cost_tracker: LiteLLMCostTracker
    tools: list[BaseTool]
    graph: StateGraph
    work_dir: Path = None
    assessment_result: Optional[ExploitabilityAssessment] = None
    max_research_iterations: int = 10
    intermediate_steps: list = []
    research_notes: list = []

    def __init__(
        self,
        model: str,
        temperature: float,
        cp_meta: CPMetadata,
        work_dir: Path,
        max_iterations: int = 15,
    ):
        api_key = os.environ.get("LITELLM_KEY")
        base_url = os.environ.get("AIXCC_LITELLM_HOSTNAME")

        self.work_dir = work_dir
        self.max_research_iterations = max_iterations  # Use max_iterations for research phase

        self.cost_tracker = LiteLLMCostTracker(model)
        self.interaction_logger = LLMInteractionLogger()

        self.llm = ChatLiteLLM(
            model=f"litellm_proxy/{model}",
            api_key=api_key,
            api_base=base_url,
            temperature=temperature,
            callbacks=[self.cost_tracker, self.interaction_logger],
            request_timeout=30
        )
        self.llm.streaming = False

        # Create LLM with structured output for assessment phase
        self.llm_with_structure = self.llm.with_structured_output(ExploitabilityAssessment)

        # Create exploration tools
        self.tools = self._create_tools(cp_meta)

        # Build the two-stage graph
        self.graph = self._build_graph()

    def _create_tools(self, cp_meta: CPMetadata) -> list[BaseTool]:
        """Create exploration tools for the research phase."""
        tools = []
        if cp_meta is not None:
            ossfuzz_root = str(cp_meta.get_proj_path()) if cp_meta.get_proj_path() else None
            source_root = str(cp_meta.get_repo_src_path()) if cp_meta.get_repo_src_path() else None

            if ossfuzz_root or source_root:
                tools.append(UnifiedReadFileTool(ossfuzz_root=ossfuzz_root, source_root=source_root))
                tools.append(UnifiedListDirectoryTool(ossfuzz_root=ossfuzz_root, source_root=source_root))
                tools.append(UnifiedFileSearchTool(ossfuzz_root=ossfuzz_root, source_root=source_root))
                logger.info(f"Added exploration tools with roots: ossfuzz={ossfuzz_root}, source={source_root}")
            else:
                logger.warning(f"{CRS_WARN} Could not determine source roots, no exploration tools added")
        return tools

    def _build_graph(self) -> StateGraph:
        """Build the two-stage LangGraph: research -> assessment."""
        workflow = StateGraph(AgentState)

        # Add nodes
        workflow.add_node("research", self._research_node)
        workflow.add_node("assessment", self._assessment_node)

        # Set entry point
        workflow.set_entry_point("research")

        # Add edges: research always goes to assessment
        workflow.add_edge("research", "assessment")
        workflow.add_edge("assessment", END)

        return workflow.compile()

    def _generate_fallback_report(self, initial_prompt: str, intermediate_steps: list) -> str:
        """Generate a report from intermediate steps when agent doesn't produce final output.

        This is used as a fallback when the research agent reaches max_iterations without
        generating a comprehensive report.
        """
        # Extract CWE from the initial prompt to include vulnerability context
        import re
        cwe_match = re.search(r'\*\*(CWE-\d+):', initial_prompt)
        cwe = cwe_match.group(1) if cwe_match else None

        # Build report header with vulnerability context
        report_lines = [
            "# Research Report (Generated from Tool Observations)",
            "",
            f"The research phase reached max iterations ({self.max_research_iterations}) without generating a final report.",
            "Below is a summary of the exploration activities:",
            ""
        ]

        # Include vulnerability description and exploitability factors if CWE is found
        if cwe:
            report_lines.extend([
                ExploitabilityPromptGenerator.get_cwe_description(cwe),
                "",
                ExploitabilityPromptGenerator.get_cwe_exploitability_factors(cwe),
                ""
            ])

        if not intermediate_steps:
            return "\n".join(report_lines + ["", "No research tools were used. Assessment based on initial code context only."])

        # Continue with tool observations
        report_lines.append("")

        # Build report with agent reasoning and tool observations
        for i, (action, observation) in enumerate(intermediate_steps, 1):
            tool_name = getattr(action, "tool", "unknown")
            tool_input = getattr(action, "tool_input", {})
            reasoning = getattr(action, "log", "")

            report_lines.append(f"## Step {i}: {tool_name}")
            report_lines.append("")

            # Add agent's reasoning/thought process
            if reasoning:
                report_lines.append("**Agent Reasoning:**")
                report_lines.append(reasoning.strip())
                report_lines.append("")

            # Add tool input
            if isinstance(tool_input, dict):
                input_str = ", ".join([f"{k}={v}" for k, v in tool_input.items()])
            else:
                input_str = str(tool_input)
            report_lines.append(f"**Tool Input:** {input_str}")
            report_lines.append("")

            # Add observation
            obs_str = str(observation)
            report_lines.append(f"**Observation:**")
            report_lines.append(obs_str)
            report_lines.append("")
            report_lines.append("---")
            report_lines.append("")

        # Add a note about incomplete analysis
        report_lines.extend([
            "## Notes",
            "",
            "- This report was auto-generated because the research agent did not produce a final summary",
            "- The assessment phase will use the above tool observations for exploitability analysis",
            "- Consider increasing max_iterations if this occurs frequently"
        ])

        return "\n".join(report_lines)

    @retry(
        wait=wait_exponential(multiplier=1, min=4, max=60),
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type((RateLimitError, FunctionTimedOut, KeyError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        after=after_log(logger, logging.INFO)
    )
    def _research_node(self, state: AgentState) -> AgentState:
        """Research phase: explore code with tools to gather information."""
        logger.info("[Research Phase] Starting code exploration...")

        if not self.tools:
            logger.info("[Research Phase] No tools available, skipping research")
            return {
                "research_notes": ["No exploration tools available - using only prompt context"],
                "research_iterations": 0
            }

        # Create research agent with tools
        research_prompt = ChatPromptTemplate.from_messages([
            ("system",
             "You are assessing the exploitability of a vulnerability sink point. "
             "Your goal is to gather information about this sink to determine if it is exploitable.\n\n"
             "Use the available tools to explore the code and gather relevant information. "
             "Focus on: data flow, input validation, accessibility, and exploitability.\n\n"
             "After exploring, you MUST provide a comprehensive research report with:\n"
             "1. Key findings about data flow (where does the input come from?)\n"
             "2. Input validation/sanitization observed (or lack thereof)\n"
             "3. Method accessibility (public API? internal only?)\n"
             "4. Relevant code snippets that support your findings\n"
             "5. Any security controls or mitigations in place\n\n"
             "Be thorough and include specific details and code references."),
            ("user", "{initial_prompt}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        research_agent = create_tool_calling_agent(self.llm, self.tools, research_prompt)
        research_executor = AgentExecutor(
            agent=research_agent,
            tools=self.tools,
            max_iterations=self.max_research_iterations,
            return_intermediate_steps=True,
            handle_parsing_errors=True,
            verbose=False  # Enable to see which tool/LLM call is hanging
        )

        # Run research with timeout
        logger.info("[Research Phase] Invoking research executor (timeout=150s)")
        result = func_timeout(150, research_executor.invoke, args=({"initial_prompt": state["initial_prompt"]},))
        logger.info("[Research Phase] Research executor completed")

        # Get the agent's final output (the comprehensive report)
        agent_output = result.get("output", "")

        # Also capture intermediate steps for reference
        intermediate_steps = result.get("intermediate_steps", [])

        # Use the agent's final output as the research note (comprehensive report)
        used_fallback = False
        if agent_output and "Agent stopped due to max iterations" not in agent_output:
            notes = [agent_output]
        else:
            used_fallback = True
            if not agent_output:
                reason = "empty output"
            elif "Agent stopped due to max iterations" in agent_output:
                reason = f"hit max iterations ({self.max_research_iterations})"
            else:
                reason = "unknown"
            logger.warning(
                f"{CRS_WARN} Research agent did not generate final report "
                f"(reason: {reason}, tool_calls: {len(intermediate_steps)}, "
                f"output_length: {len(agent_output)}), creating fallback from tool observations"
            )
            if agent_output:
                logger.debug(f"[Research Phase] Raw agent output: {agent_output[:500]}")
            notes = [self._generate_fallback_report(state["initial_prompt"], intermediate_steps)]

        logger.info(
            f"[Research Phase] Completed with {len(intermediate_steps)} tool calls, "
            f"report: {len(notes[0])} chars{' (FALLBACK)' if used_fallback else ''}"
        )

        return {
            "research_notes": notes,
            "research_iterations": len(intermediate_steps),
            "intermediate_steps": intermediate_steps,
            "used_fallback_report": used_fallback,
        }

    @retry(
        wait=wait_exponential(multiplier=1, min=4, max=60),
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type((RateLimitError, FunctionTimedOut, KeyError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        after=after_log(logger, logging.INFO)
    )
    def _assessment_node(self, state: AgentState) -> AgentState:
        """Assessment phase: use structured output to assess exploitability."""
        logger.info("[Assessment Phase] Making final exploitability assessment...")

        # Build assessment prompt with research findings
        research_summary = "\n".join(state.get("research_notes", []))

        assessment_prompt = (
            f"{state['initial_prompt']}\n\n"
            f"## Research Findings\n\n"
            f"{research_summary if research_summary else 'No additional research performed.'}\n\n"
            f"## Final Assessment\n\n"
            f"Based on the code context and research findings above, decide whether this sink is likely exploitable.\n"
            f"Set unexploitable=True if the sink is very unlikely exploitable.\n"
            f"Set unexploitable=False if the sink is possibly exploitable.\n"
            f"Provide your assessment in structured format."
        )

        # Get structured assessment with timeout
        logger.info("[Assessment Phase] Invoking LLM with structured output (timeout=60s)")
        assessment = func_timeout(60, self.llm_with_structure.invoke, args=(assessment_prompt,), kwargs={'tool_choice': 'auto'})
        logger.info("[Assessment Phase] LLM call completed")
        self.assessment_result = assessment

        if self.assessment_result is None:
            logger.error(f"{CRS_ERR} Assessment phase failed to produce a result")
        else:
            logger.info(f"[Assessment Phase] Result: {'NOT exploitable' if assessment.unexploitable else 'Potentially exploitable'}")

        return {"assessment": assessment}

    def run(self, query: str) -> Dict:
        """Run the two-stage exploitability assessment agent.

        Stage 1: Research phase with exploration tools
        Stage 2: Assessment phase with structured output
        """
        logger.info("[Agent] Starting agent execution")

        # Initialize state
        initial_state = {
            "initial_prompt": query,
            "research_notes": [],
            "research_iterations": 0,
            "used_fallback_report": False,
            "assessment": None,
            "intermediate_steps": []
        }

        logger.info("[Agent] Invoking LangGraph workflow")
        # Run the graph
        final_state = self.graph.invoke(initial_state)
        logger.info("[Agent] LangGraph workflow completed")

        # Store results for logging even if assessment fails
        self.intermediate_steps = final_state.get("intermediate_steps", [])
        self.research_notes = final_state.get("research_notes", [])
        used_fallback = final_state.get("used_fallback_report", False)

        # Validate that assessment was generated
        if not self.assessment_result:
            logger.error(f"{CRS_ERR} Assessment phase failed to produce a result")
            raise RuntimeError("Assessment result is None - agent failed to generate assessment")

        logger.info(
            f"[Agent] Agent execution completed successfully"
            f"{' (used fallback report)' if used_fallback else ''}"
        )
        # Return result in expected format
        return {
            "output": f"Exploitability: {'NOT exploitable' if self.assessment_result.unexploitable else 'Potentially exploitable'}",
            "assessment": self.assessment_result,
            "intermediate_steps": self.intermediate_steps,
            "research_notes": self.research_notes,
            "used_fallback_report": used_fallback,
        }

    def get_exploitability_assessment(self) -> bool:
        """Get the exploitability assessment (True = NOT exploitable, False = potentially exploitable)."""
        if self.assessment_result:
            return self.assessment_result.unexploitable
        return False  # Default to potentially exploitable if no assessment

    def get_assessment_reasoning(self) -> str | None:
        """Get the reasoning for the exploitability assessment."""
        if self.assessment_result:
            return self.assessment_result.reasoning
        return None

    def get_cost_summary(self) -> str:
        summary = self.cost_tracker.get_summary()
        return (f"Total Cost: ${summary['total_cost']}, "
                f"Total Tokens: {summary['total_tokens']} "
                f"(Prompt: {summary['total_prompt_tokens']}, "
                f"Completion: {summary['total_completion_tokens']}), "
                f"LLM Calls: {summary['num_llm_calls']}")
