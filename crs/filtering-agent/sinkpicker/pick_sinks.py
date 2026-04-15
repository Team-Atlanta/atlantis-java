#!/usr/bin/env python3

import argparse
import json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .cpmeta import CPMetadata
from .assessor_agent import ExploitabilityAssessor
from .assessor_prompt import ExploitabilityPromptGenerator
from .callgraph import CallGraph
from .utils import CRS_ERR_LOG, CRS_WARN_LOG

CRS_ERR = CRS_ERR_LOG("pick_sinks")
CRS_WARN = CRS_WARN_LOG("pick_sinks")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


try:
    from libCRS.otel import install_otel_logger
    install_otel_logger(action_name="crs-java:filtering-agent")
except Exception as e:
    print(f"{CRS_ERR} Failed to install OpenTelemetry logger: {e}.")

# Force reconfigure all handlers to include thread name
# (in case OpenTelemetry or other libraries changed the format)
formatter = logging.Formatter("%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s")
for handler in logging.root.handlers:
    handler.setFormatter(formatter)


def _run_agent_assessment(
    agent: ExploitabilityAssessor,
    prompt: str,
    sink_id: str,
) -> tuple[bool, str, dict, bool]:
    """
    Run agent assessment and return results.

    Returns:
        tuple of (unexploitable, reasoning, result_dict, has_assessment_error)
    """
    logger.info(f"[Thread] Running exploitability assessment for {sink_id}...")

    try:
        result = agent.run(prompt)
        result["_initial_prompt"] = prompt

        unexploitable = agent.get_exploitability_assessment()
        reasoning = agent.get_assessment_reasoning()

        # Check if assessment was actually generated
        if unexploitable is None or reasoning is None:
            logger.error(f"{CRS_ERR} Assessment result incomplete for {sink_id}")
            return False, "Assessment generation failed", result, True

        logger.info(f"[Thread] Exploitability assessment for {sink_id}: {'NOT exploitable' if unexploitable else 'potentially exploitable'}")
        logger.info(f"[Thread] Reasoning: {reasoning}")
        logger.info(f"[Thread] Cost: {agent.get_cost_summary()}")

        return unexploitable, reasoning, result, False

    except RuntimeError as e:
        # Assessment generation failed — preserve research notes from the agent
        logger.error(f"{CRS_ERR} Assessment generation failed for {sink_id}: {e}")
        return False, str(e), {
            "_initial_prompt": prompt,
            "research_notes": getattr(agent, "research_notes", []),
            "output": "",
        }, True


def _save_agent_log(
    workdir_path: Path,
    sink_idx: int,
    sink_id: str,
    file_path: str,
    line_num: int,
    cwe: str,
    max_iterations: int,
    result: dict,
    unexploitable: bool,
    reasoning: str,
    agent: ExploitabilityAssessor,
    used_fallback_report: bool = False,
) -> Path:
    """Save agent execution log to workdir."""
    safe_sink_id = sink_id.replace("/", "_").replace("\\", "_").replace(":", "_")
    steps_file = workdir_path / f"agent_steps_{sink_idx}_{safe_sink_id}.txt"

    with open(steps_file, "w") as f:
        # Header
        f.write("="*80 + "\n")
        f.write("EXPLOITABILITY ASSESSMENT LOG\n")
        f.write("="*80 + "\n\n")
        f.write(f"Sink ID:          {sink_id}\n")
        f.write(f"File:             {file_path}\n")
        f.write(f"Line:             {line_num}\n")
        f.write(f"Sink Index:       {sink_idx}\n")
        f.write(f"CWE:              {cwe}\n\n")

        # Initial prompt
        f.write("="*80 + "\n")
        f.write("INITIAL PROMPT\n")
        f.write("="*80 + "\n\n")
        initial_prompt = result.get("_initial_prompt", "(prompt not available)")
        f.write(initial_prompt)
        f.write("\n\n")

        # Research findings (comprehensive report)
        research_notes = result.get("research_notes", [])
        f.write("="*80 + "\n")
        if used_fallback_report:
            f.write("RESEARCH REPORT (FALLBACK - agent did not generate final report)\n")
        else:
            f.write("RESEARCH REPORT\n")
        f.write("="*80 + "\n\n")
        if research_notes:
            for note in research_notes:
                f.write(note)
                f.write("\n\n")
        else:
            f.write("No research report available.\n\n")

        # Final assessment
        f.write("="*80 + "\n")
        f.write("FINAL ASSESSMENT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Exploitability: {'NOT exploitable (unexploitable=True)' if unexploitable else 'Potentially exploitable (unexploitable=False)'}\n\n")
        f.write(f"Reasoning:\n{reasoning if reasoning else 'No reasoning provided'}\n\n")
        f.write(f"Agent Output:\n{result.get('output', '(no output)')}\n\n")

        # Cost summary
        cost_summary = agent.cost_tracker.get_summary()
        f.write("="*80 + "\n")
        f.write("COST SUMMARY\n")
        f.write("="*80 + "\n\n")
        f.write(f"Total Cost:            ${cost_summary['total_cost']:.6f}\n")
        f.write(f"Total Tokens:          {cost_summary['total_tokens']}\n")
        f.write(f"Prompt Tokens:         {cost_summary['total_prompt_tokens']}\n")
        f.write(f"Completion Tokens:     {cost_summary['total_completion_tokens']}\n")
        f.write(f"Number of LLM Calls:   {cost_summary['num_llm_calls']}\n\n")

        if cost_summary.get('cost_breakdown'):
            f.write("Per-call Breakdown:\n")
            for idx, call in enumerate(cost_summary['cost_breakdown'], 1):
                f.write(f"  Call {idx}: {call['total_tokens']} tokens, ${call['cost']:.6f}\n")

        f.write("\n" + "="*80 + "\n")

    logger.info(f"[Thread] Saved agent steps to {steps_file}")

    # Dump raw LLM interactions for debugging
    llm_log_file = workdir_path / f"llm_calls_{sink_idx}_{safe_sink_id}.txt"
    agent.interaction_logger.dump(llm_log_file)
    logger.info(f"[Thread] Saved LLM interactions ({len(agent.interaction_logger.interactions)} calls) to {llm_log_file}")

    return steps_file


def process_single_sink(
    sink_idx: int,
    sink: dict,
    gen_model: str,
    temperature: float,
    cp_meta: CPMetadata,
    workdir_path: Path,
    max_iterations: int,
    prompt_gen: ExploitabilityPromptGenerator,
    cwe: str,
    total_sinks: int,
) -> dict:
    """
    Process a single sink using an agent to assess exploitability.

    Returns a dict with:
        - success: bool
        - sink_id: str
        - unexploitable: bool (True if NOT exploitable, False if potentially exploitable)
        - reasoning: str
        - cost_summary: dict
        - sink_index: int
        - steps_file: Path
        - error: str (if failed)
    """
    file_path = sink["coord"]["file_name"]
    sink_id = sink["id"]
    line_num = sink["coord"]["line_num"]

    logger.info(f"{'='*80}")
    logger.info(f"Analyzing sink #{sink_idx}: {sink_id}")
    logger.info(f"Location: {file_path}:{line_num}")

    try:
        # Create agent and generate prompt
        agent = ExploitabilityAssessor(
            model=gen_model,
            temperature=temperature,
            cp_meta=cp_meta,
            work_dir=workdir_path,
            max_iterations=max_iterations,
        )
        prompt = prompt_gen.generate_exploitability_prompt(sink)

        # Run assessment
        unexploitable, reasoning, result, has_assessment_error = _run_agent_assessment(agent, prompt, sink_id)
        used_fallback = result.get("used_fallback_report", False)

        # Save execution log
        steps_file = _save_agent_log(
            workdir_path, sink_idx, sink_id, file_path, line_num,
            cwe, max_iterations, result, unexploitable, reasoning, agent,
            used_fallback_report=used_fallback,
        )

        # Prepare cost summary
        cost_summary = agent.cost_tracker.get_summary()
        cost_summary["sink_id"] = sink_id
        cost_summary["sink_index"] = sink_idx
        cost_summary["unexploitable"] = unexploitable

        if used_fallback:
            logger.warning(f"[Thread] Sink {sink_id}: used fallback report (agent did not generate research report)")

        logger.info(f"Completed sink #{sink_idx}: {sink_id}")
        return {
            "success": True,
            "sink_id": sink_id,
            "unexploitable": unexploitable,
            "reasoning": reasoning,
            "cost_summary": cost_summary,
            "sink_index": sink_idx,
            "steps_file": steps_file,
            "used_fallback_report": used_fallback,
            "has_assessment_error": has_assessment_error,
        }

    except Exception as e:
        logger.error(f"{CRS_ERR} Error processing sink {sink_id}: {e}")
        logger.error(traceback.format_exc())
        return {
            "success": False,
            "sink_id": sink_id,
            "sink_index": sink_idx,
            "error": str(e),
        }


def run_for_single_pair(
    sinks: list[dict],
    harness: str,
    cwe: str,
    gen_model: str,
    temperature: float,
    cp_meta: CPMetadata,
    call_graph: CallGraph,
    workdir_path: Path,
    max_iterations: int,
    max_workers: int,
    force_agent_analysis: bool = False,
) -> tuple[dict, dict, dict]:
    """
    Run exploitability assessment for a single harness:CWE pair.

    Returns:
        tuple of (unexploitable_harnesses, in_final_result_harnesses, cost_overview)
        where the first two dicts map sink_id -> harness (for sinks that are unexploitable/in_final_result for this harness)
    """
    logger.info(f"{'='*80}")
    logger.info(f"Processing pair: {harness}:{cwe}")
    logger.info(f"{'='*80}")

    # === Determine input sink set ===
    # Step 1: Filter by harness, CWE, and existing filters (Set A)
    set_a = [
        s for s in sinks
        if s.get("cwe") == cwe
        and not s.get("filtered_out_flow", False)
        and not s.get("filtered_out_test", False)
    ]
    logger.info(f"Set A (harness={harness}, CWE={cwe}, not filtered): {len(set_a)} sinks")

    if not set_a:
        logger.warning(f"{CRS_WARN} No sinks found for {harness}:{cwe} after filtering.")
        return {}, {}, None  # No sinks for this harness

    # Step 2: Check if Set A has <= 10 sinks
    if len(set_a) <= 10:
        input_sink_set = set_a
        logger.info(f"Set A has <= 10 sinks. Using Set A as input sink set.")
    else:
        # Step 3: Filter by reachability (Set B)
        set_b = [s for s in set_a if s.get("reachable", False)]
        logger.info(f"Set B (reachable from Set A): {len(set_b)} sinks")

        # Step 4: Determine input sink set based on Set B size
        if len(set_b) == 0:
            input_sink_set = set_a
            logger.info(f"Set B is empty. Using Set A as input sink set.")
        elif len(set_b) <= 10:
            input_sink_set = set_b
            logger.info(f"Set B has <= 10 sinks. Using Set B as input sink set.")
        else:
            # Set B has > 10 sinks, need to run agent analysis
            input_sink_set = set_b
            logger.info(f"Set B has > 10 sinks. Will analyze all {len(set_b)} sinks.")

    logger.info(f"{'='*80}")
    logger.info(f"Input sink set determined: {len(input_sink_set)} sinks to analyze")

    # === Run Exploitability Analysis ===
    # If input sink set has <= 10 sinks and not forcing analysis, skip agent analysis
    if len(input_sink_set) <= 10 and not force_agent_analysis:
        logger.info(f"Input sink set has <= 10 sinks. Skipping agent analysis.")
        # All sinks in input_sink_set are in final result for this harness (no agent analysis)
        in_final_result_harnesses = {s["id"]: harness for s in input_sink_set}
        return {}, in_final_result_harnesses, None

    # If forcing analysis or input sink set has > 10 sinks, run agent analysis
    if force_agent_analysis and len(input_sink_set) <= 10:
        logger.info(f"Input sink set has <= 10 sinks, but --force-agent-analysis is enabled. Running agent analysis.")

    # Create workdir for agent analysis artifacts
    workdir_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Using pair workdir: {workdir_path}")

    # Create prompt generator
    prompt_gen = ExploitabilityPromptGenerator(cp_meta, cwe, harness, call_graph)

    # Track which sinks are unexploitable/in_final_result for this harness
    unexploitable_harnesses = {}  # sink_id -> harness (for sinks that are unexploitable)
    in_final_result_harnesses = {}  # sink_id -> harness (for sinks that are in_final_result)
    exploitability_by_sink_id = {}  # sink_id -> unexploitable (bool) - for tracking stats
    all_cost_summaries = []

    # Error tracking
    no_report_count = 0  # Missing research reports
    no_assessment_count = 0  # Missing assessment results
    total_errors = 0  # Total failed sinks

    # Process sinks in parallel
    total_sinks = len(input_sink_set)
    logger.info(f"{'='*80}")
    logger.info(f"Running exploitability assessment on {total_sinks} sinks in parallel...")

    # Prepare sink processing tasks
    sink_tasks = [
        (sink_idx, sink)
        for sink_idx, sink in enumerate(input_sink_set, 1)
    ]

    # Use ThreadPoolExecutor to process sinks in parallel
    # Using threads since the work is I/O-bound (API calls)
    actual_workers = min(total_sinks, max_workers)  # Don't create more workers than sinks
    logger.info(f"Using {actual_workers} parallel workers")

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        # Submit all tasks
        future_to_sink = {
            executor.submit(
                process_single_sink,
                sink_idx,
                sink,
                gen_model,
                temperature,
                cp_meta,
                workdir_path,
                max_iterations,
                prompt_gen,
                cwe,
                total_sinks,
            ): (sink_idx, sink["id"])
            for sink_idx, sink in sink_tasks
        }

        # Process completed tasks as they finish
        count = 1
        for future in as_completed(future_to_sink):
            sink_idx, sink_id = future_to_sink[future]
            try:
                result = future.result()

                # By default, assume sink is in final result (for failures)
                in_final_result_harnesses[sink_id] = harness

                if result["success"]:
                    # Track exploitability assessment
                    unexploitable = result["unexploitable"]
                    exploitability_by_sink_id[sink_id] = unexploitable

                    # Update harness tracking based on exploitability
                    if unexploitable:
                        # Sink is unexploitable for this harness
                        unexploitable_harnesses[sink_id] = harness
                        # Remove from in_final_result for this harness
                        if sink_id in in_final_result_harnesses:
                            del in_final_result_harnesses[sink_id]
                    else:
                        # Sink is potentially exploitable, keep in final result
                        in_final_result_harnesses[sink_id] = harness

                    # Collect cost summary
                    all_cost_summaries.append(result["cost_summary"])

                    # Track errors
                    if result.get("used_fallback_report", False):
                        no_report_count += 1
                        logger.warning(f"{CRS_WARN} Used fallback research report for sink {sink_id}")

                    if result.get("has_assessment_error", False):
                        no_assessment_count += 1
                        logger.error(f"{CRS_ERR} Missing assessment result for sink {sink_id}")

                    logger.info(f"Completed sink #{sink_idx} ({count}/{total_sinks}): {sink_id} - {'NOT exploitable' if unexploitable else 'Potentially exploitable'}")
                else:
                    total_errors += 1
                    # On complete failure, keep in final result (conservative)
                    logger.error(f"Failed to process sink #{sink_idx} ({count}/{total_sinks}): {sink_id} - Error: {result.get('error')}")

            except Exception as e:
                logger.error(f"{CRS_ERR} Exception getting result for {sink_id}: {e}")
                logger.error(traceback.format_exc())

            count += 1

    logger.info(f"{'='*80}")
    logger.info(f"Completed processing all {total_sinks} sinks in parallel")

    # Report on errors
    if total_errors > 0 or no_report_count > 0 or no_assessment_count > 0:
        logger.warning(f"{'='*80}")
        logger.warning(f"ERROR SUMMARY")
        logger.warning(f"{'='*80}")
        if total_errors > 0:
            logger.error(f"{CRS_ERR} Complete failures (exceptions): {total_errors}/{total_sinks}")
        if no_report_count > 0:
            logger.warning(f"{CRS_WARN} Fallback research reports: {no_report_count}/{total_sinks}")
        if no_assessment_count > 0:
            logger.error(f"{CRS_ERR} Missing assessment results: {no_assessment_count}/{total_sinks}")
        logger.warning(f"{'='*80}\n")
    else:
        logger.info(f"All {total_sinks} sinks processed successfully with reports and assessments")

    # Calculate cost summary
    total_cost = sum(s["total_cost"] for s in all_cost_summaries)
    total_tokens = sum(s["total_tokens"] for s in all_cost_summaries)
    total_prompt_tokens = sum(s["total_prompt_tokens"] for s in all_cost_summaries)
    total_completion_tokens = sum(s["total_completion_tokens"] for s in all_cost_summaries)
    total_llm_calls = sum(s["num_llm_calls"] for s in all_cost_summaries)

    # Count exploitable vs unexploitable
    exploitable_count = sum(1 for v in exploitability_by_sink_id.values() if not v)
    unexploitable_count = sum(1 for v in exploitability_by_sink_id.values() if v)

    cost_overview = {
        "harness": harness,
        "cwe": cwe,
        "pair": f"{harness}:{cwe}",
        "total_sinks_analyzed": len(exploitability_by_sink_id),
        "exploitable_sinks": exploitable_count,
        "unexploitable_sinks": unexploitable_count,
        "errors": {
            "total_failures": total_errors,
            "fallback_reports": no_report_count,
            "missing_assessments": no_assessment_count,
        },
        "overall_cost": round(total_cost, 6),
        "overall_tokens": total_tokens,
        "overall_prompt_tokens": total_prompt_tokens,
        "overall_completion_tokens": total_completion_tokens,
        "overall_llm_calls": total_llm_calls,
        "per_sink_costs": all_cost_summaries,
    }

    # Save CWE-specific cost overview
    cost_file = workdir_path / "cost_overview.json"
    with open(cost_file, "w") as f:
        json.dump(cost_overview, f, indent=2)
    logger.info(f"{'='*80}")
    logger.info(f"Saved cost overview to {cost_file}")
    logger.info(f"Total Cost: ${cost_overview['overall_cost']}")
    logger.info(f"Total Tokens: {cost_overview['overall_tokens']}")
    logger.info(f"Total LLM Calls: {cost_overview['overall_llm_calls']}")
    logger.info(f"Exploitable: {exploitable_count}, Unexploitable: {unexploitable_count}")

    # Log error summary
    if total_errors > 0 or no_report_count > 0 or no_assessment_count > 0:
        logger.info(f"Errors: {total_errors} failures, {no_report_count} fallback reports, {no_assessment_count} missing assessments")

    return unexploitable_harnesses, in_final_result_harnesses, cost_overview


def run(
    input_path: str,
    output_path: str,
    metadata_path: str,
    harness_cwe_pairs: str,
    call_graph_path: str,
    workdir: str = None,
    gen_model: str = "gpt-5",
    max_iterations: int = 15,
    temperature: float = 0.0,
    verbose: bool = False,
    max_workers: int = 10,
    force_agent_analysis: bool = False,
):
    """Run exploitability assessment on sink candidates."""

    try:
        # Load input JSON
        logger.info(f"Loading input from {input_path}")
        with open(input_path, "r") as f:
            sinks = json.load(f)

        logger.info(f"Loaded {len(sinks)} total sink locations")

        # Load call graph
        logger.info(f"Loading call graph from {call_graph_path}")
        with open(call_graph_path, "r") as f:
            call_graph_data = json.load(f)
        logger.info(f"Loaded call graph with {len(call_graph_data.get('nodes', []))} nodes and {len(call_graph_data.get('links', []))} edges")

        # Create CallGraph instance
        call_graph = CallGraph(call_graph_data)

        # Parse harness:CWE pairs (comma-separated list)
        pairs = []
        for pair_str in harness_cwe_pairs.split(","):
            pair_str = pair_str.strip()
            if not pair_str:
                continue
            if ":" not in pair_str:
                logger.error(f"{CRS_ERR} Invalid harness:CWE pair format: {pair_str}")
                raise ValueError(f"Invalid pair format: {pair_str}. Expected 'harness:CWE'")
            harness, cwe = pair_str.split(":", 1)
            pairs.append((harness.strip(), cwe.strip()))

        logger.info(f"Analyzing {len(pairs)} harness:CWE pair(s): {', '.join(f'{h}:{c}' for h, c in pairs)}")

        logger.info(f"Generation model: {gen_model}")

        # Load metadata
        cp_meta = CPMetadata(metadata_path)

        # Prepare base workdir
        base_workdir_path = Path(workdir) if workdir else Path.cwd() / "exploitability_workdir"
        base_workdir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using base workdir: {base_workdir_path}")

        # Track all exploitability assessments and final result flags across all pairs
        all_exploitability_by_sink_id = {}  # sink_id -> unexploitable (bool)
        all_in_final_result_by_sink_id = {}  # sink_id -> in_final_result (bool)
        all_cost_overviews = []

        # Process each harness:CWE pair independently
        for harness, cwe in pairs:
            logger.info(f"{'='*80}")
            logger.info(f"Starting analysis for {harness}:{cwe}")
            logger.info(f"{'='*80}")

            # Prepare pair-specific workdir path (will be created only if needed)
            pair_workdir_path = base_workdir_path / f"{harness}_{cwe}"

            # Run analysis for this pair
            unexploitable_harnesses, in_final_result_harnesses, cost_overview = run_for_single_pair(
                sinks,
                harness,
                cwe,
                gen_model,
                temperature,
                cp_meta,
                call_graph,
                pair_workdir_path,
                max_iterations,
                max_workers,
                force_agent_analysis,
            )

            # Merge results - aggregate harnesses into lists
            for sink_id, harness_name in unexploitable_harnesses.items():
                if sink_id not in all_exploitability_by_sink_id:
                    all_exploitability_by_sink_id[sink_id] = []
                all_exploitability_by_sink_id[sink_id].append(harness_name)

            for sink_id, harness_name in in_final_result_harnesses.items():
                if sink_id not in all_in_final_result_by_sink_id:
                    all_in_final_result_by_sink_id[sink_id] = []
                all_in_final_result_by_sink_id[sink_id].append(harness_name)
            if cost_overview:
                all_cost_overviews.append(cost_overview)

            logger.info(f"{'='*80}")
            logger.info(f"Completed analysis for {harness}:{cwe}")
            logger.info(f"{'='*80}")

        # Create combined cost overview
        if all_cost_overviews:
            combined_cost = sum(c["overall_cost"] for c in all_cost_overviews)
            combined_tokens = sum(c["overall_tokens"] for c in all_cost_overviews)
            combined_prompt_tokens = sum(c["overall_prompt_tokens"] for c in all_cost_overviews)
            combined_completion_tokens = sum(c["overall_completion_tokens"] for c in all_cost_overviews)
            combined_llm_calls = sum(c["overall_llm_calls"] for c in all_cost_overviews)
            combined_sinks_analyzed = sum(c["total_sinks_analyzed"] for c in all_cost_overviews)
            combined_exploitable = sum(c["exploitable_sinks"] for c in all_cost_overviews)
            combined_unexploitable = sum(c["unexploitable_sinks"] for c in all_cost_overviews)

            combined_overview = {
                "pairs_analyzed": [f"{h}:{c}" for h, c in pairs],
                "total_sinks_analyzed": combined_sinks_analyzed,
                "exploitable_sinks": combined_exploitable,
                "unexploitable_sinks": combined_unexploitable,
                "overall_cost": round(combined_cost, 6),
                "overall_tokens": combined_tokens,
                "overall_prompt_tokens": combined_prompt_tokens,
                "overall_completion_tokens": combined_completion_tokens,
                "overall_llm_calls": combined_llm_calls,
                "per_pair_costs": all_cost_overviews,
            }

            # Save combined cost overview
            combined_cost_file = base_workdir_path / "cost_overview.json"
            with open(combined_cost_file, "w") as f:
                json.dump(combined_overview, f, indent=2)
            logger.info(f"{'='*80}")
            logger.info(f"Saved combined cost overview to {combined_cost_file}")
            logger.info(f"Total Cost: ${combined_overview['overall_cost']}")
            logger.info(f"Total Tokens: {combined_overview['overall_tokens']}")
            logger.info(f"Total LLM Calls: {combined_overview['overall_llm_calls']}")
            logger.info(f"Total Sinks Analyzed: {combined_sinks_analyzed}")
            logger.info(f"Exploitable: {combined_exploitable}, Unexploitable: {combined_unexploitable}")

        # Update all sinks with unexploitable and in_final_result fields
        logger.info(f"{'='*80}")
        logger.info(f"Updating sink entries with exploitability assessments...")

        for sink in sinks:
            sink_id = sink["id"]
            # Only add unexploitable field for analyzed sinks
            if sink_id in all_exploitability_by_sink_id:
                sink["unexploitable"] = all_exploitability_by_sink_id[sink_id]
            # Add in_final_result field for sinks in input_sink_set
            if sink_id in all_in_final_result_by_sink_id:
                sink["in_final_result"] = all_in_final_result_by_sink_id[sink_id]

        # Write output
        logger.info(f"Writing output to {output_path}")
        with open(output_path, "w") as f:
            json.dump(sinks, f, indent=2)

        logger.info("Exploitability assessment completed successfully")

    except Exception as e:
        logger.error(f"{CRS_ERR} Fatal error: {e}")
        logger.error(traceback.format_exc())
        raise


def main():
    """Main entry point for the exploitability assessment tool."""
    parser = argparse.ArgumentParser(
        description="AI-powered exploitability assessment tool for vulnerability sink points"
    )
    parser.add_argument("input", help="Path to input JSON file with sink candidates")
    parser.add_argument("output", help="Path to save output JSON file")
    parser.add_argument(
        "--metadata", required=True, help="Path to the CP metadata JSON file"
    )
    parser.add_argument(
        "--harness-cwe-pairs", required=True, help="Comma-separated list of harness:CWE pairs (e.g., 'harness1:CWE-022,harness2:CWE-089,harness3:CWE-022'). Each pair is analyzed independently."
    )
    parser.add_argument(
        "--call-graph", required=True, help="Path to call graph JSON file (Joern format)"
    )
    parser.add_argument(
        "--workdir", default=None, help="Working directory for agent artifacts"
    )
    parser.add_argument(
        "--gen-model",
        default="gpt-5",
        help="LLM model used by the filtering agent. Default: gpt-5",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=15,
        help="Maximum number of agent iterations. Default: 15",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="LLM temperature for agent. Default: 0.0",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum number of parallel workers for processing files. Default: 10",
    )
    parser.add_argument(
        "--force-agent-analysis",
        action="store_true",
        help="Force agent analysis even when input sink set has ≤10 sinks. Default: False (skip analysis for ≤10 sinks)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    run(
        args.input,
        args.output,
        args.metadata,
        args.harness_cwe_pairs,
        args.call_graph,
        args.workdir,
        args.gen_model,
        args.max_iterations,
        args.temperature,
        args.verbose,
        args.max_workers,
        args.force_agent_analysis,
    )


if __name__ == "__main__":
    main()
