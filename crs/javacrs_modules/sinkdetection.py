#!/usr/bin/env python3
import asyncio
import json
import os
import shlex
import time
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
from libCRS import CRS, HarnessRunner, Module
from pydantic import BaseModel, Field, field_validator

from .base_objs import Sinkpoint
from .utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    get_env_exports,
    get_env_or_abort,
    run_process_and_capture_output,
)

CRS_ERR = CRS_ERR_LOG("sinkdetection-mod")
CRS_WARN = CRS_WARN_LOG("sinkdetection-mod")


CWE_TO_MARK_DESC = {
    "CWE-022": "sink-FilePathTraversal",
    "CWE-078": "sink-OsCommandInjection",
    "CWE-089": "sink-SqlInjection",
    "CWE-090": "sink-LdapInjection",
    "CWE-094": "sink-ScriptEngineInjection",
    "CWE-117": "sink-RemoteJNDILookup",
    "CWE-470": "sink-OsCommandInjection",
    "CWE-502": "sink-RemoteCodeExecution",
    "CWE-611": "sink-ServerSideRequestForgery",
    "CWE-643": "sink-XPathInjection",
    "CWE-730": "sink-RegexInjection",
    "CWE-918": "sink-ServerSideRequestForgery",
}

ALL_CWES = sorted(CWE_TO_MARK_DESC.keys())


class SinkDetectionParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable or disable this module."
    )
    cwes: List[str] = Field(
        default_factory=lambda: list(ALL_CWES),
        description="**Optional**, subset of supported CWEs to detect. Any CWE not in the 12 supported CWEs is rejected.",
    )
    gen_model: str = Field(
        "gpt-5",
        description="**Optional**, LLM model used by the filtering agent.",
    )
    max_iterations: int = Field(
        15,
        description="**Optional**, max iterations for filtering agent.",
    )
    max_workers: int = Field(
        10,
        description="**Optional**, max parallel workers for filtering agent.",
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v

    @field_validator("cwes")
    def cwes_must_be_supported(cls, v):
        invalid = [c for c in v if c not in ALL_CWES]
        if invalid:
            raise ValueError(
                f"Unsupported CWEs {invalid}. Supported: {ALL_CWES}"
            )
        return v


class SinkDetection(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: SinkDetectionParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.params = params
        self.enabled = self.params.enabled
        # Resolve the CWE list once: empty means "all 12 supported CWEs".
        self.cwes: List[str] = list(self.params.cwes) if self.params.cwes else list(ALL_CWES)
        self.workdir = self.get_workdir("") / self.crs.cp.name
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.db = Path("/out/crs/codeql-db")
        self.results_file = self.workdir / "codeql_result.json"
        self.reachable_file = self.workdir / "reachable_sinks.json"
        self.results_file.parent.mkdir(parents=True, exist_ok=True)
        self.java_crs_src = Path(get_env_or_abort("JAVA_CRS_SRC"))
        self.tool_cwd = self.java_crs_src / "codeql"
        self.filtering_agent_dir = self.java_crs_src / "filtering-agent"

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner: HarnessRunner):
        pass

    async def _async_get_mock_result(self, hrunner):
        pass

    async def _create_command_sh(
        self,
        cmd: List[str],
        script_name: str,
        working_dir: str,
        timeout: int,
        cpu_list: List[int],
        buffer_output: bool,
        log_prefix: str,
    ) -> Path:
        if timeout:
            cmd = ["timeout", "-s", "SIGKILL", f"{timeout}s"] + cmd
        if cpu_list:
            cpu_str = ",".join(map(str, cpu_list))
            cmd = ["taskset", "-c", cpu_str] + cmd
        if buffer_output:
            cmd = ["stdbuf", "-e", "0", "-o", "0"] + cmd

        cmd_str = " ".join(shlex.quote(str(arg)) for arg in cmd)
        command_sh_content = f"""#!/bin/bash
# Env
{get_env_exports(os.environ)}
# Cmd
{f'cd "{working_dir}"' if working_dir else ''}
{cmd_str} > {str(self.workdir.resolve())}/{log_prefix}.log 2>&1
"""
        command_sh = self.workdir / script_name
        async with aiofiles.open(command_sh, "w") as f_sh:
            await f_sh.write(command_sh_content)
        command_sh.chmod(0o755)
        return command_sh

    async def _run_codeql_query(self, cpu_list: List[int]):
        """Run CodeQL queries via run.sh."""
        self.logH(None, f"Running CodeQL queries with CPUs: {cpu_list}")

        # Always pass the resolved CWE list (guaranteed non-empty subset of the 12).
        os.environ["CODEQL_CWES"] = ",".join(self.cwes)
        self.logH(None, f"CodeQL CWEs: {self.cwes}")

        try:
            rest_time = self.crs.rest_time()
            if rest_time <= 0:
                self.logH(None, f"{CRS_WARN} No time left to run CodeQL queries")
                return

            script_path = self.tool_cwd / "run.sh"
            if not script_path.exists():
                raise FileNotFoundError(f"CodeQL script not found: {script_path}")

            cmd_args = [
                str(script_path),
                str(self.db),
                str(self.results_file),
            ]

            command_sh = await self._create_command_sh(
                cmd_args,
                "command_run.sh",
                str(self.tool_cwd),
                timeout=rest_time,
                cpu_list=cpu_list,
                buffer_output=True,
                log_prefix="query",
            )

            self.logH(None, f"Running CodeQL command: {command_sh}")
            log_file = self.workdir / "run.log"

            ret = await run_process_and_capture_output(command_sh, log_file)
            if ret == 0:
                self.logH(
                    None,
                    f"CodeQL queries finished (ret: {ret}) in {time.time() - self.crs.start_time:.2f}s",
                )
            else:
                self.logH(
                    None,
                    f"{CRS_ERR} CodeQL queries exited with ret {ret} in {time.time() - self.crs.start_time:.2f}s",
                )

        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} CodeQL query error: {str(e)} {traceback.format_exc()}",
            )

    async def _run_reachability_filter(self, call_graph_path: Path) -> Path:
        """Annotate CodeQL results with reachability and drop filtered_out sinks.

        Writes to self.reachable_file without modifying the raw CodeQL results.
        Returns the path of the file downstream stages should consume
        (reachable_file on success, raw results_file on failure).
        """
        script_path = self.tool_cwd / "find_reachable_sinks.py"
        if not script_path.exists():
            self.logH(None, f"{CRS_WARN} find_reachable_sinks.py not found, skipping reachability filter")
            return self.results_file

        self.logH(None, f"Running reachability filter with call graph: {call_graph_path}")
        cmd = [
            "python3", str(script_path),
            str(self.results_file),
            str(call_graph_path),
            "--output", str(self.reachable_file),
        ]
        command_str = " ".join(shlex.quote(str(arg)) for arg in cmd)
        command_sh_content = f"""#!/bin/bash
# Env
{get_env_exports(os.environ)}
# Cmd
cd "{self.tool_cwd}"
{command_str} > "{self.workdir / 'reachability.log'}" 2>&1
"""
        command_sh = self.workdir / "reachability.sh"
        async with aiofiles.open(command_sh, "w") as f:
            await f.write(command_sh_content)
        command_sh.chmod(0o755)

        ret = await run_process_and_capture_output(
            command_sh, self.workdir / "reachability_run.log"
        )
        if ret == 0 and self.reachable_file.exists():
            self.logH(None, f"Reachability filter completed, output: {self.reachable_file}")
            return self.reachable_file

        self.logH(None, f"{CRS_WARN} Reachability filter exited with ret {ret}, using raw CodeQL results")
        return self.results_file

    def _build_harness_cwe_pairs(self) -> str:
        """Build harness:CWE pairs string from configured harnesses and CWEs."""
        harnesses = self.crs.get_target_harnesses()
        pairs = [f"{h}:{c}" for h in harnesses for c in self.cwes]
        return ",".join(pairs)

    def _get_empty_call_graph_path(self) -> Path:
        """Create and return path to an empty call graph placeholder."""
        empty_cg = self.workdir / "empty-cg.json"
        if not empty_cg.exists():
            empty_cg.write_text('{"nodes": [], "links": []}')
        return empty_cg

    async def _wait_for_call_graph(self) -> Path:
        """Wait for a call graph to become available.

        If llmpocgen is enabled, waits for its Joern CG. Otherwise checks
        static analysis and SARIF listener CGs. Falls back to empty CG
        if nothing becomes available before CRS time runs out.
        """
        # Determine which CG to wait for based on enabled modules
        primary_wait = None
        if hasattr(self.crs, 'llmpocgen') and self.crs.llmpocgen.enabled:
            primary_wait = self.crs.llmpocgen.joern_cg_file
            self.logH(None, "Waiting for llmpocgen Joern call graph...")

        # All candidates to check while waiting
        candidates = []
        if hasattr(self.crs, 'staticanalysis') and hasattr(self.crs.staticanalysis, 'soot_cg_file'):
            candidates.append(self.crs.staticanalysis.soot_cg_file)
        if hasattr(self.crs, 'sariflistener') and hasattr(self.crs.sariflistener, 'full_cg_file'):
            candidates.append(self.crs.sariflistener.full_cg_file)
        if hasattr(self.crs, 'llmpocgen') and hasattr(self.crs.llmpocgen, 'joern_cg_file'):
            candidates.append(self.crs.llmpocgen.joern_cg_file)

        while self.crs.should_continue():
            # If we have a primary wait target, check it first
            if primary_wait and primary_wait.exists():
                self.logH(None, f"Using call graph: {primary_wait}")
                return primary_wait

            # Check all candidates
            for cg in candidates:
                if cg.exists():
                    self.logH(None, f"Using call graph: {cg}")
                    return cg

            await asyncio.sleep(5)

        # Time ran out — use empty placeholder
        self.logH(None, f"{CRS_WARN} No call graph available before timeout, using empty placeholder")
        return self._get_empty_call_graph_path()

    async def _run_filtering_agent(
        self, results_json: Path, cpu_list: List[int], call_graph_path: Path
    ) -> Path:
        """Run pick_sinks.py to assess exploitability. Returns path to results to use."""
        assessed_output = self.workdir / "assessed_sinks.json"
        pick_sinks_script = self.filtering_agent_dir / "sinkpicker" / "pick_sinks.py"

        if not pick_sinks_script.exists():
            self.logH(None, f"{CRS_WARN} pick_sinks.py not found at {pick_sinks_script}, using raw results")
            return results_json

        harness_cwe_pairs = self._build_harness_cwe_pairs()
        self.logH(None, f"Filtering agent harness-CWE pairs: {harness_cwe_pairs}")
        self.logH(None, f"Filtering agent call graph: {call_graph_path}")

        command = [
            "timeout", "-s", "SIGKILL", f"{self.crs.rest_time()}s",
            "taskset", "-c", ",".join(map(str, cpu_list)),
            "python3.12",
            "-m", "sinkpicker.pick_sinks",
            str(results_json),
            str(assessed_output),
            "--metadata", str(self.crs.meta.meta_path.resolve()),
            "--harness-cwe-pairs", harness_cwe_pairs,
            "--call-graph", str(call_graph_path),
            "--gen-model", self.params.gen_model,
            "--max-workers", str(self.params.max_workers),
            "--max-iterations", str(self.params.max_iterations),
        ]

        command_str = " ".join(shlex.quote(str(arg)) for arg in command)
        command_sh_content = f"""#!/bin/bash
# Env
{get_env_exports(os.environ)}
# Cmd
cd "{self.filtering_agent_dir}"
{command_str} > "{self.workdir / 'pick_sinks.log'}" 2>&1
"""
        command_sh = self.workdir / "pick_sinks.sh"
        async with aiofiles.open(command_sh, "w") as f:
            await f.write(command_sh_content)
        command_sh.chmod(0o755)

        self.logH(None, "Running filtering agent...")
        ret = await run_process_and_capture_output(
            command_sh, self.workdir / "pick_sinks_run.log"
        )

        if ret == 0 and assessed_output.exists():
            self.logH(None, "Filtering agent completed successfully")
            return assessed_output
        else:
            self.logH(
                None,
                f"{CRS_WARN} Filtering agent exited with ret {ret}, falling back to raw CodeQL results",
            )
            return results_json

    async def _update_sink(self, sink_dict: dict) -> bool:
        """Resolve bytecode and feed a single sink to sinkmanager."""
        try:
            cwe = sink_dict.get("cwe")
            mark_desc = CWE_TO_MARK_DESC.get(cwe)
            if mark_desc is None:
                self.logH(
                    None,
                    f"{CRS_WARN} Skipping sinkpoint with unknown CWE '{cwe}' (no mark_desc mapping)",
                )
                return False

            # Honor the filtering agent's verdict: keep the sink only if at
            # least one harness in `in_final_result` is a harness the CRS is
            # actually targeting in this run.
            in_final_result = sink_dict.get("in_final_result") or []
            target_harnesses = set(self.crs.get_target_harnesses())
            matched_harnesses = [h for h in in_final_result if h in target_harnesses]
            if not matched_harnesses:
                self.logH(
                    None,
                    f"{CRS_WARN} Skipping sinkpoint (cwe={cwe}): agent in_final_result={in_final_result} "
                    f"has no overlap with targeted harnesses {sorted(target_harnesses)}",
                )
                return False

            coord_dict = sink_dict["coord"]
            code_coord = self.crs.query_code_coord(
                coord_dict["class_name"], coord_dict["line_num"]
            )
            if code_coord is None:
                self.logH(
                    None,
                    f"{CRS_WARN} Filter out sinkpoint {coord_dict['class_name']}:{coord_dict['line_num']} which has no code coordinate",
                )
                return False

            self.logH(
                None,
                f"Sinkpoint {coord_dict['class_name']}:{coord_dict['line_num']} found code coordinate: {code_coord}",
            )
            coord_dict.update(asdict(code_coord))
            coord_dict["mark_desc"] = mark_desc
            sink = Sinkpoint.frm_dict(sink_dict)
            self.logH(
                None,
                f"Feeding sinkpoint to sinkmanager (matched harnesses={matched_harnesses}): {sink}",
            )
            await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="sinkdetection")
            return True
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} updating sink {sink_dict} to sinkmanager: {str(e)} {traceback.format_exc()}",
            )
            return False

    async def _feed_sinks_to_sinkmanager(self, results_path: Path):
        """Parse sink results and feed each to sinkmanager."""
        self.logH(None, f"Parsing results from {results_path}")
        try:
            if not results_path.exists():
                self.logH(None, f"{CRS_ERR} Results file not found: {results_path}")
                return

            async with aiofiles.open(results_path, "r") as f:
                results = await f.read()

            sinkpoints = json.loads(results)
            if not isinstance(sinkpoints, list):
                self.logH(None, f"{CRS_ERR} Invalid results format: expected list")
                return

            total_sinks = len(sinkpoints)
            self.logH(None, f"Found {total_sinks} sinkpoints in results")

            kept_sinks = 0
            for sink_dict in sinkpoints:
                if await self._update_sink(sink_dict):
                    kept_sinks += 1

            filtered_sinks = total_sinks - kept_sinks
            self.logH(
                None, f"Sinkpoints stats: {filtered_sinks} filtered, {kept_sinks} kept"
            )

        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Result parsing error: {str(e)} {traceback.format_exc()}",
            )

    async def _async_run(self, _) -> Dict[str, Any]:
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled")
            return

        self.logH(None, f"Starting {self.name}")

        try:
            cpu_list = await self.crs.cpuallocator.poll_allocation(None, self.name)
            self.logH(None, f"Allocated CPUs: {cpu_list}")

            if not self.db.exists():
                self.logH(None, f"{CRS_ERR} CodeQL database not found at {self.db}, skipping")
                return

            # 1. Run CodeQL queries
            self.logH(None, f"Using CodeQL database at {self.db}")
            await self._run_codeql_query(cpu_list)

            if not self.results_file.exists():
                self.logH(None, f"{CRS_ERR} CodeQL produced no results, skipping")
                return

            # 2. Wait for call graph and run reachability filter
            call_graph_path = await self._wait_for_call_graph()
            reachable_sinks_file = await self._run_reachability_filter(call_graph_path)

            # 3. Run filtering agent
            assessed_file = await self._run_filtering_agent(reachable_sinks_file, cpu_list, call_graph_path)

            # 4. Feed filtered sinks to sinkmanager
            await self._feed_sinks_to_sinkmanager(assessed_file)

        except Exception as e:
            self.logH(
                None, f"{CRS_ERR} Module failed: {str(e)} {traceback.format_exc()}"
            )

        self.logH(None, f"{self.name} ended")
