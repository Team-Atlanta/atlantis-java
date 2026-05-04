#!/usr/bin/env python3

from datetime import datetime
import json
import logging
import os
import traceback
import uuid
from pathlib import Path

from ..beepobjs import BeepSeed
from ..cpmeta import CPMetadata
from ..fuzzer.jazzer import JazzerFuzzer
from ..redis import RedisCacheClient
from ..utils import CRS_ERR_LOG, CRS_WARN_LOG, get_usable_cpu_id
from ..agent import ExpkitExecutionContext
from .prompt import PromptGenerator

logger = logging.getLogger(__name__)


CRS_ERR = CRS_ERR_LOG("sinkexp")
CRS_WARN = CRS_WARN_LOG("sinkexp")


class SinkpointExpTool:
    """Handles exploitation of sinkpoint BEEPs."""

    def __init__(
        self,
        redis_client: RedisCacheClient,
        beepseed: BeepSeed,
        exp_time: int,
        cp_meta: CPMetadata,
        workdir: Path = None,
        gen_model: str = None,
        skip_redis_cache: bool = False,
        output_formats: list[str] = None,
        max_iterations: int = 30,
        trim_context: bool = True,
    ):
        self.beepseed = beepseed
        self.redis_client = redis_client
        self.gen_model = gen_model
        self.exp_time = exp_time
        self.cp_meta = cp_meta
        self.workdir = workdir
        self.cpu_id = get_usable_cpu_id()
        self.prompt_generator = PromptGenerator(cp_meta, beepseed, trim_context=trim_context)
        self.skip_redis_cache = skip_redis_cache
        self.output_formats = output_formats if output_formats is not None else ["hexstring", "bytes", "script"]
        self.max_iterations = max_iterations

    def check_exp_status(self, fuzz_log: Path) -> bool:
        if not fuzz_log.exists():
            logger.warning(f"{CRS_ERR} Fuzz log file {fuzz_log} does not exist")
            return False

        try:
            with open(fuzz_log, "rb") as f:
                in_stack_trace = False

                for line in f:
                    try:
                        line_str = line.decode("utf-8", errors="ignore").strip()
                    except UnicodeDecodeError as e:
                        logger.warning(f"Error decoding line: {e}")
                        continue

                    if "== Java Exception:" in line_str:
                        if "FuzzerSecurityIssue" not in line_str:
                            continue

                        if "Stack overflow" in line_str or "Out of memory" in line_str:
                            continue

                        in_stack_trace = True

                    elif in_stack_trace:
                        if "== libFuzzer crashing input ==" in line_str:
                            in_stack_trace = False
                            continue

                        # match if sinkpoint location is in the stack trace line
                        class_name = self.beepseed.coord.class_name.replace("/", ".")
                        method_name = self.beepseed.coord.method_name
                        line_no = self.beepseed.coord.line_num
                        file_name = self.beepseed.coord.file_name
                        signature = f"{class_name}.{method_name}({file_name}:{line_no})"
                        if signature in line_str:
                            logger.info("Found successful exploitation in logs")
                            return True

                logger.info("No successful exploitation found in logs")
                return False

        except Exception as e:
            logger.error(f"Error checking exploitation status: {e}")
            return False

    def _dump_deepgen_task(self):
        """Dump the exploitation script to crs."""
        try:
            task_req_dir = os.environ.get("DEEPGEN_TASK_REQ_DIR", None)
            if task_req_dir is None:
                logger.warning(
                    f"{CRS_WARN} Environment variable DEEPGEN_TASK_REQ_DIR is not set, skipping script dump"
                )
            task_req_dir = Path(task_req_dir)
            if not task_req_dir.exists():
                task_req_dir.mkdir(parents=True, exist_ok=True)

            task_id = (
                f"exp-{self.beepseed.target_harness}-{self.beepseed.coord.key_shasum()}"
            )
            task_json = task_req_dir / f"{task_id}.json"
            script_prompt = self.prompt_generator.generate_poc_script()
            local_task_json = self.workdir / f"{task_id}.json"
            with open(local_task_json, "w") as f:
                f.write(
                    json.dumps(
                        [
                            {
                                "task_id": task_id,
                                "target_harness": self.beepseed.target_harness,
                                "script_prompt": script_prompt,
                            }
                        ],
                        indent=2,
                    )
                )
            # atomically replace the file in the task request directory
            os.replace(local_task_json, task_json)
            logger.info(f"Exploitation script dumped successfully to {task_json}")
        except Exception as e:
            logger.error(f"{CRS_ERR} Failed to dump exploitation script: {e}")

    def _add_beepseed_to_corpus(self, jazzer):
        """Extract beepseed data and add it to the corpus."""
        if not self.beepseed.data_hex_str:
            logger.warning("Data is empty in beepseed")
            return None

        try:
            beepseed_bytes = bytes.fromhex(self.beepseed.data_hex_str)
            beepseed_file = jazzer.add_corpus_file(beepseed_bytes, "beepseed")
            logger.info(f"Added beepseed to corpus ({len(beepseed_bytes)} bytes)")
            return beepseed_file
        except Exception as e:
            logger.error(f"{CRS_ERR} Failed to add beepseed to corpus: {e}")
            return None

    def _serialize_steps(self, result: dict) -> str:
        """Serialize intermediate steps to a string."""

        result_str = []

        result_str.append("=" * 80 + "\n")
        result_str.append("AGENT THOUGHT PROCESS LOG\n")
        result_str.append("=" * 80 + "\n\n")
        result_str.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        result_str.append(f"INPUT:\n{result.get('input', '')}\n\n")
        result_str.append("-" * 80 + "\n\n")

        # Write each step
        for i, step in enumerate(result.get("intermediate_steps", []), 1):
            agent_action, observation = step

            result_str.append(f"STEP {i}:\n\n")
            result_str.append(f"Thought/Reasoning:\n{agent_action.log}\n\n")
            result_str.append(f"Action:\n  Tool: {agent_action.tool}\n")
            result_str.append(f"  Input: {agent_action.tool_input}\n\n")
            result_str.append(f"Observation/Result:\n{observation}\n\n")
            result_str.append("-" * 80 + "\n\n")

        result_str.append(f"FINAL OUTPUT:\n{result.get('output', '')}\n\n")
        result_str.append("=" * 80 + "\n")

        return "".join(result_str)


    def _add_poc_to_corpus(self, jazzer, execution_context):
        """Generate POC content using LLM and add to corpus."""
        try:
            logger.info("Generating POC using LLM")
            steps_until_solved = None
            # check cache first
            x_hexstr = self.redis_client.get(self.beepseed, self.gen_model, "x_hexstr")
            if x_hexstr is not None and not self.skip_redis_cache:
                logger.info(
                    f"CACHE: Found cached x_hexstr in Redis: {x_hexstr} for {self.beepseed.redis_key()}"
                )
            else:
                logger.info(
                    f"CACHE: No cached x_hexstr found, generating new one for {self.beepseed.redis_key()}"
                )
                try:
                    poc_prompt = self.prompt_generator.generate_poc_prompt()
                    if self.workdir:
                        prompt_file = self.workdir / "poc_prompt.txt"
                        with open(prompt_file, "w") as f:
                            f.write(poc_prompt)
                        logger.info(f"Initial prompt saved to {prompt_file} ({len(poc_prompt)} chars)")
                    poc_response = execution_context.run(poc_prompt)
                    # Save response to a file in the workdir for debugging
                    if self.workdir:
                        if 'output' in poc_response:
                            resp_file = self.workdir / f"poc_response.txt"
                            with open(resp_file, "w") as f:
                                f.write(poc_response['output'])
                            logger.info(f"LLM response saved to {resp_file}")
                        if 'intermediate_steps' in poc_response:
                            steps_file = self.workdir / f"intermediate_steps.txt"
                            with open(steps_file, "w") as f:
                                f.write(self._serialize_steps(poc_response))
                            logger.info(f"LLM response saved to {steps_file}")

                            # Also parse the tool result to determine in which step the solution was found
                            for i, step in enumerate(poc_response.get("intermediate_steps", []), 1):
                                _, observation = step
                                if "Exploit successful" in observation:
                                    steps_until_solved = i
                                    logger.info(f"Solution found at step {steps_until_solved}")
                                    break
                    x_hexstr = execution_context.solution()
                    logger.info(f"LLM solution: {x_hexstr}")

                    if x_hexstr is None:
                        logger.warning(
                            "CACHE: LLM returned None for x_hexstr, set it as empty string"
                        )
                        x_hexstr = ""

                except Exception as e:
                    logger.info(
                        f"Failed to generate a poc: {e}, unable to cache POC hex string, will retry later: {traceback.format_exc()}"
                    )
                    return None, None

                logger.info(
                    f"CACHE: Setting POC hex string in Redis cache for {self.beepseed.redis_key()}"
                )
                self.redis_client.set(
                    self.beepseed, self.gen_model, "x_hexstr", x_hexstr
                )

            # Parse hex strings from using bytes
            try:
                poc_bytes = bytes.fromhex(x_hexstr)
                if poc_bytes:
                    poc_file = jazzer.add_corpus_file(poc_bytes, "poc")
                    logger.info(f"Added POC to corpus ({len(poc_bytes)} bytes)")
                    return poc_file, steps_until_solved
            except Exception as e:
                logger.warning(f"Invalid LLM-generated hex string in POC content: {e}")
                return None, None

        except Exception as e:
            logger.error(
                f"Failed to generate and add POC to corpus: {e} {traceback.format_exc()}"
            )
        return None, None

    def exploit(self) -> dict:
        """Perform sinkpoint beepseed exploitation."""
        try:
            target_harness = self.beepseed.target_harness
            target_classpath = self.cp_meta.get_classpath(target_harness)

            if self.workdir:
                work_dir = self.workdir
                fuzz_id = f"exp-{self.beepseed.data_sha1[:8]}"
                logger.info(f"Using provided working directory: {work_dir}")
            else:
                fuzz_id = (
                    f"exploit-{self.beepseed.data_sha1[:8]}-{uuid.uuid4().hex[:8]}"
                )
                work_dir = Path(f"/tmp/{fuzz_id}")
                logger.info(f"Using generated working directory: {work_dir}")

            if not target_classpath or not target_harness:
                raise ValueError(
                    f"Missing classpath {target_classpath} or {target_harness} in CP metadata"
                )

            logger.info(
                f"Initializing fuzzer for {target_harness} with classpath {target_classpath} (workdir={work_dir})"
            )

            jazzer = JazzerFuzzer(
                jazzer_dir=os.environ.get("AIXCC_JAZZER_DIR"),
                work_dir=work_dir,
                cp_name=self.cp_meta.get_cp_name(),
                target_harness=target_harness,
                fuzz_target=self.cp_meta.get_target_class(target_harness),
                target_classpath=target_classpath,
                custom_sink_conf_path=self.cp_meta.get_custom_sink_conf_path(),
                cpu_id=self.cpu_id,
                custom_args=[
                    '-use_value_profile=1 --trace=none --instrumentation_includes="some.package.names.never.exist" '
                ],
            )

            execution_context = ExpkitExecutionContext(
                self.gen_model, 1.0,
                jazzer, self.beepseed,
                work_dir,
                self.output_formats,
                self.cp_meta,
                self.max_iterations
            )

            # self._dump_deepgen_task()
            self._add_beepseed_to_corpus(jazzer)
            poc_file, steps_until_solved = self._add_poc_to_corpus(jazzer, execution_context)

            exp_succ = False
            if not poc_file:
                logger.error(f"{CRS_ERR} No valid POC added to corpus, skipping jazzer")
                result = {
                    "status": False,
                    "error": "No valid POC added to corpus, skipping exploitation",
                    "workdir": str(work_dir),
                    "fuzz_id": fuzz_id,
                }

            else:
                logger.info(f"Running fuzzer for {self.exp_time}s with ID {fuzz_id}")

                result_json = jazzer.fuzz(
                    fuzz_id=fuzz_id, fuzz_time=self.exp_time, mem_size=4096
                )
                exp_succ = self.check_exp_status(jazzer.fuzz_log)
                tool_call_solved = execution_context.tool_call_solved()
                result = {
                    "status": exp_succ,
                    "tool_call_solved": tool_call_solved,
                    "steps_until_solved": steps_until_solved,
                    "cp_name": self.cp_meta.get_cp_name(),
                    "coordinate": self.beepseed.coord.to_dict(),
                    "workdir": str(work_dir),
                    "fuzz_id": fuzz_id,
                    "results_json": str(result_json) if result_json else None,
                }

            logger.info(f"Exploitation completed with status: {exp_succ}")
            logger.info(f"Cost summary: {execution_context.get_cost_summary_verbose()}")
            return result

        except Exception as e:
            err_str = f"{CRS_ERR} Exception {e}"
            logger.error(f"{err_str} with traceback:\n{traceback.format_exc()}")
            return {"status": False, "error": err_str}
