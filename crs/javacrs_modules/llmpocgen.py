#!/usr/bin/env python3
import asyncio
import base64
import copy
import hashlib
import json
import os
import shlex
import traceback
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List, Literal

import aiofiles
from libCRS import CRS, HarnessRunner, Module, util
from pydantic import BaseModel, Field, field_validator

from .base_objs import DiffReachabilityReport, Sinkpoint
from .jazzer import is_fuzzing_module
from .utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    get_env_exports,
    get_env_or_abort,
    run_process_and_capture_output,
)
from .utils_nfs import get_crs_java_pod_cache_llmpocgen_dir

CRS_ERR = CRS_ERR_LOG("llmpocgen-mod")
CRS_WARN = CRS_WARN_LOG("llmpocgen-mod")


class LLMPOCGeneratorParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )
    mode: Literal["crs", "static", "onetime"] = Field(
        ...,
        description="**Mandatory**, mode of `llmpocgen` module, one of 'crs' or 'static' or 'onetime', static mode is for testing purpose.",
    )
    models: List[str] = Field(
        default_factory=lambda: [
            "claude-opus-4-20250514",
            "o3",
            "claude-sonnet-4-20250514",
            "gemini-2.5-pro",
            "gpt-4.1",
        ],
        description="**Optional**, list of available LLM models. Tasks use their own preference order but are constrained to this set. Default: all supported models.",
    )
    scan_sinks: bool = Field(
        True,
        description="**Optional**, whether llmpocgen should run its own Joern-based sink discovery (FROM_INSIDE). Default: True. Set to False to rely solely on sinks from the CRS sinkmanager.",
    )
    diff_max_len: int = Field(
        65536,
        description="Maximum length for diff content processing, must be between 16K and 512K.",
    )
    worker_num: int = Field(
        2,
        description="Number of worker processes to use for parallel processing.",
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v

    @field_validator("mode")
    def mode_cannot_be_empty(cls, v):
        if not v:
            raise ValueError("mode cannot be empty")
        return v

    @field_validator("diff_max_len")
    def diff_max_len_in_range(cls, v):
        if v <= 0:
            raise ValueError("diff_max_len must be positive")
        if v < 16384:
            raise ValueError("diff_max_len must be at least 16384 (16K)")
        if v > 524288:
            raise ValueError("diff_max_len must not exceed 524288 (512K)")
        return v

    @field_validator("worker_num")
    def worker_num_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("worker_num must be positive")
        return v


class LLMPOCGenerator(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: LLMPOCGeneratorParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.jazzer_path = Path(get_env_or_abort("AIXCC_JAZZER_DIR")) / "jazzer"
        self.joern_dir = Path(get_env_or_abort("JOERN_DIR"))
        self.tool_cwd = Path(get_env_or_abort("JAVA_CRS_SRC")) / "llm-poc-gen"
        self.workdir = self.get_workdir("") / self.crs.cp.name
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.params = params
        self.enabled = self.params.enabled

        self.mode = self.params.mode
        self.diff_max_len = str(self.params.diff_max_len)
        self.worker_num = str(self.params.worker_num)
        self.ttl_fuzz_time = self.crs.ttl_fuzz_time
        self.sent_pocs = set()

        self.joern_cg_file = self.workdir / "joern-cg.json"
        self.joern_cg_file.parent.mkdir(parents=True, exist_ok=True)

        self._diff_lock = asyncio.Lock()
        self._diff_ana_results = DiffReachabilityReport()  # Empty report

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner: HarnessRunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner: HarnessRunner | None):
        util.TODO("Add mock result")

    async def _gen_command_script(
        self,
        output_dir: Path,
        cpu_list: List[int],
        run_log: Path,
    ) -> Path:
        """Generates a shell script to execute the LLM POC generator."""
        # Only feed CP.harnesses this CRS instance is responsible for
        harness_ids = [hr.harness.name for hr in self.crs.hrunners]
        input_cg_paths = [
            str(self.crs.sariflistener.full_cg_file.resolve()),
            str(self.crs.staticanalysis.soot_cg_file.resolve()),
        ]
        command = [
            "timeout",
            "-s",
            "SIGKILL",
            f"{str(self.ttl_fuzz_time)}s",
            "taskset",
            "-c",
            ",".join(map(str, cpu_list)),
            "/venv/bin/poetry",
            "run",
            "python3.12",
            "-u",
            "-m",
            "vuli.main",
            f"--cp_meta={self.crs.meta.meta_path.resolve()}",
            f"--jazzer={self.jazzer_path.resolve()}",
            f"--joern_dir={self.joern_dir.resolve()}",
            f"--output_dir={output_dir.resolve()}",
            "--log_level=DEBUG",
            "--harnesses",
            ",".join(harness_ids),
            "--mode",
            self.mode,
        ]

        command.extend(
            [
                "--cg",
                ",".join(input_cg_paths),
                "--server_dir",
                str(get_crs_java_pod_cache_llmpocgen_dir().resolve()),
                "--diff_threashold",
                self.diff_max_len,
                "--worker",
                self.worker_num,
                "--models",
                ",".join(self.params.models),
            ]
            + (["--scan-sinks"] if self.params.scan_sinks else [])
        )
        command_str = " ".join(shlex.quote(str(arg)) for arg in command)
        # N.B. stdout & stderr are redirected to avoid python pipe OOM issues
        command_sh_content = f"""#!/bin/bash
# Env
{get_env_exports(os.environ)}
# Cmd
cd "{str(self.tool_cwd.resolve())}"
{command_str} > "{run_log.resolve()}" 2>&1
"""

        command_sh = output_dir / "command.sh"
        async with aiofiles.open(command_sh, "w") as f:
            await f.write(command_sh_content)
        command_sh.chmod(0o755)

        return command_sh

    async def _async_gen_blackboard(
        self, workdir: Path, cp_name: str, cpu_list: List[int]
    ):
        """Creates the blackboard by running llm-poc-gen."""
        self.logH(None, f"Running llm-poc-gen for CP {cp_name}")
        run_log = workdir / "run.log"
        command_sh = await self._gen_command_script(workdir, cpu_list, run_log)
        self.logH(None, f"Executing command.sh at {command_sh.resolve()}")

        self.logH(None, "Running llm-poc-gen command.sh...")
        ret = await run_process_and_capture_output(command_sh, workdir / "run.log")

        if ret == 137 and not self.crs.should_continue():
            # killed by SIGKILL and timeout
            self.logH(None, f"llm-poc-gen is force ended (ret {ret})")
        else:
            # It is abnormal as long as we are not killed by SIGKILL
            self.logH(None, f"{CRS_ERR} llm-poc-gen unexpectedly exits with ret {ret}")

        # Notify jazzer about end of llm-poc-gen
        await self._notify_jazzer()

    async def _async_parse_blackboard(
        self,
        blackboard_path: Path,
        pocs_output_dir: Path,
        sinkpoints,
        elapsed_seconds: int,
    ) -> bool:
        """Parses the blackboard file, extracts POCs, and saves them."""
        if not blackboard_path.exists():
            self.logH(None, f"'blackboard' file not found at '{blackboard_path}'.")
            return False

        try:
            async with aiofiles.open(blackboard_path, "r") as bb_file:
                blackboard = json.loads(await bb_file.read())
        except Exception as e:
            self.logH(
                None,
                f"{CRS_WARN} Error reading 'blackboard': {e} {traceback.format_exc()}",
            )
            return False

        # Extract poc blobs and save
        pocs = []
        for info in blackboard.get("result", []):
            harness_id = info.get("harness_id", None)
            if harness_id is None or "blob" not in info:
                continue
            for encoded_str in info["blob"]:
                try:
                    poc = base64.b64decode(encoded_str)
                    poc_hash = hashlib.sha256(poc).hexdigest()
                    output_file_path = pocs_output_dir / f"{harness_id}-poc-{poc_hash}"
                    if output_file_path.exists():
                        continue
                    pocs.append((poc, output_file_path))
                except Exception as e:
                    self.logH(
                        None,
                        f"{CRS_ERR} Error decoding base64 string: {e} {traceback.format_exc()}",
                    )

        for poc, output_file_path in pocs:
            try:
                async with aiofiles.open(output_file_path, "wb") as output_file:
                    await output_file.write(poc)
            except Exception as e:
                self.logH(
                    None,
                    f"{CRS_ERR} Error writing to file '{output_file_path}': {e} {traceback.format_exc()}",
                )
        if pocs:
            self.logH(None, f"Extracted and saved {len(pocs)} new POCs.")
            for poc in pocs:
                self.logH(
                    None,
                    f"POC {poc[1].name} is generated in {elapsed_seconds} seconds",
                )

        # Extract sinkpoints
        sinkpoints.extend(blackboard.get("sinks", {}))

        # Update diff analysis results
        try:
            report = DiffReachabilityReport.frm_llmpocgen(blackboard)
            await self._update_diff_ana_results(report)
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Error updating diff analysis results: {e} {traceback.format_exc()}",
            )

        return True

    async def _send_pocs_to_jazzers(self, pocs_output_dir: Path):
        """For each Jazzer module, send all generated POCs matches harnesses IDs."""
        for mod in self.crs.modules:
            if not is_fuzzing_module(mod) or not mod.enabled:
                continue

            for poc_file in pocs_output_dir.iterdir():
                if not poc_file.is_file():
                    continue

                poc_key = (mod.name, poc_file.name)
                if poc_key in self.sent_pocs:
                    continue

                hrunner = next(
                    (
                        hr
                        for hr in self.crs.hrunners
                        if poc_file.name.startswith(f"{hr.harness.name}-poc-")
                    ),
                    None,
                )
                if hrunner is None:
                    self.logH(
                        None,
                        f"{CRS_ERR} POC file '{poc_file.name}' does not match any harness ID.",
                    )
                    continue

                await mod.add_corpus_file(hrunner, poc_file)
                self.sent_pocs.add(poc_key)

    async def _process_sinkpoints(self, sinkpoints, processed_sinkpoints):
        """Handles sinkpoints by sending them to the sink manager."""
        if not self.crs.sinkmanager.enabled:
            return

        """
        [
          {
            "class_name": "com.example.ClassName", // Mandatory, must be fully qualified class name (also with $ for nested classes)
            "file_name": "ClassName.java", // Optional, base file name of the class
            "line_num": 42, // Mandatory, line number of the sinkpoint
            "type": [
              "sink-desc", // keys in https://github.com/Team-Atlanta/CRS-java/blob/1a26a3136d02f2ae1fe5fb97b528e4665833178a/crs/expkit/expkit/sinkpoint_beep/prompt.py#L13, let me know if not enough or not accurate, e.g., timeout, etc.
              ..
            ], // Mandatory, list of sinkpoint types
            "in_diff": true, // Mandatory, if the sinkpoint is related to diff code and should be prioritized
            "ana_reachability": [
              "harness_id1",
              "harness_id2"
            ], // Optional, list of harness IDs that can reach this sinkpoint
            "ana_exploitability": [
              "harness_id1",
              "harness_id2"
            ], // Optional, list of harness IDs that can reach this sinkpoint
          },
          ...
        ]
        """
        for sinkpoint in sinkpoints:
            try:
                sinkpoint_hash = hashlib.sha256(
                    json.dumps(sinkpoint, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if sinkpoint_hash in processed_sinkpoints:
                    self.logH(
                        None, f"Sinkpoint {sinkpoint_hash} already processed, skipping."
                    )
                    continue
                else:
                    # NOTE: mark as processed at beginning to avoid keeping raising exp since same hash means same processing
                    processed_sinkpoints[sinkpoint_hash] = sinkpoint

                code_coord = self.crs.query_code_coord(
                    sinkpoint["class_name"], sinkpoint["line_num"]
                )
                sink_dict = {"ana_reachability": {}, "ana_exploitability": {}}
                for k, v in sinkpoint.items():
                    if k == "ana_reachability":
                        for harness_id in v:
                            sink_dict["ana_reachability"][harness_id] = True
                    elif k == "ana_exploitability":
                        # TODO: change this once llmpocgen updated this format
                        pass
                    else:
                        sink_dict[k] = v
                if code_coord:
                    self.logH(
                        None,
                        f"Sinkpoint {sinkpoint['class_name']}:{sinkpoint['line_num']} found code coordinate: {code_coord}",
                    )
                    sink_dict.update(asdict(code_coord))
                else:
                    self.logH(
                        None,
                        f"{CRS_WARN} Code coordinate not found for {sinkpoint['class_name']}:{sinkpoint['line_num']}",
                    )
                # NOTE: we just randomly pick the first type as mark_desc, as full type tag is maintained in sinkpoint.type
                sink_dict["mark_desc"] = sink_dict["type"][0]

                # Notify sink manager
                sink = Sinkpoint.frm_dict(sink_dict)
                self.logH(None, f"llmpocgen update sinkpoint to sinkmanager: {sink}")
                await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="llmpocgen")

            except Exception as e:
                self.logH(
                    None,
                    f"{CRS_ERR} processing sinkpoint {sinkpoint}: {e} {traceback.format_exc()}",
                )

    async def _update_diff_ana_results(self, diff_analysis):
        """
        {
           "diff" : {
             "harnesses": [
               "harness_A": # only reachable harness name will be listed
               ..
              ],
           }
           "merged_sarif_cg": "hash" or "",
           "merged_soot_cg": "hash" or "",
           "merged_joern_cg": "hash",
           ..
        }
        """
        async with self._diff_lock:
            self._diff_ana_results = copy.deepcopy(diff_analysis)

    async def get_diff_ana_results(self) -> dict:
        """Returns a copy of the diff analysis results."""
        async with self._diff_lock:
            results = copy.deepcopy(self._diff_ana_results)
        return results

    async def _async_monitor_blackboard(self, workdir: Path, blackboard_path: Path):
        """Monitors blackboard file for updates and processes sinkpoints & POCs."""

        pocs_output_dir = workdir / "pocs"
        pocs_output_dir.mkdir(parents=True, exist_ok=True)
        processed_sinkpoints = {}

        previous_mtime = None
        start_time = datetime.now()
        while self.crs.should_continue():
            elapsed_seconds = (datetime.now() - start_time).total_seconds()
            if elapsed_seconds > self.ttl_fuzz_time:
                self.logH(
                    None,
                    f"Module {self.name} reached TTL time of {self.ttl_fuzz_time} seconds, stopping.",
                )
                break

            if blackboard_path.exists():
                stat = blackboard_path.stat()
                mtime = stat.st_mtime

                if mtime != previous_mtime:
                    self.logH(
                        None,
                        f"Detected update to 'blackboard' file at {blackboard_path}",
                    )

                    sinkpoints = []
                    succ_loaded = await self._async_parse_blackboard(
                        blackboard_path,
                        pocs_output_dir,
                        sinkpoints,
                        elapsed_seconds,
                    )
                    await self._send_pocs_to_jazzers(pocs_output_dir)
                    await self._process_sinkpoints(sinkpoints, processed_sinkpoints)

                    if succ_loaded:
                        # Keep last successful one's mtime
                        previous_mtime = mtime

            await asyncio.sleep(1)

    async def _notify_jazzer(self):
        """Notifies all enabled Jazzer modules that LLM POC generation is done."""
        for mod in self.crs.modules:
            if is_fuzzing_module(mod) and mod.enabled:
                self.logH(None, f"Notifying Jazzer module {mod.name} of llm-poc-gen completion.")
                await mod.notify_llm_poc_gen_done()

    async def _async_run(self, _):
        """Runs the LLMPOCGenerator module for a given CP."""
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled, skipping.")
            return

        cpu_list = await self.crs.cpuallocator.poll_allocation(None, self.name)
        cp_name = self.crs.cp.name
        self.logH(
            None,
            f"Module {self.name} for CP '{cp_name}' will use CPU cores: {cpu_list}",
        )

        try:
            self.logH(None, f"Module {self.name} running")

            blackboard_path = self.workdir / "blackboard"

            # Create monitor task
            monitor_task = asyncio.create_task(
                self._async_monitor_blackboard(self.workdir, blackboard_path)
            )

            # Wait for gen_blackboard to finish
            try:
                await self._async_gen_blackboard(self.workdir, cp_name, cpu_list)
            finally:
                # Cancel monitor when gen_blackboard finishes
                monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    self.logH(None, "Blackboard monitor cancelled after gen_blackboard finished")

        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Module {self.name} encountered an exception: {e} for CP {cp_name}, traceback: \n{traceback.format_exc()}",
            )

        finally:
            self.logH(
                None,
                f"Module {self.name} finished for CP {cp_name}, marking as not running cpu intensive task",
            )
