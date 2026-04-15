#!/usr/bin/env python3
import asyncio
import json
import os
import shlex
import shutil
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
from libCRS import CRS, HarnessRunner, Module, util
from pydantic import BaseModel, Field, field_validator

from .base_objs import InsnCoordinate, Sinkpoint
from .utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    get_env_exports,
    get_env_or_abort,
    run_process_and_capture_output,
)
from .utils_nfs import get_crs_java_pod_cache_static_ana_dir

CRS_ERR = CRS_ERR_LOG("static-ana-mod")
CRS_WARN = CRS_WARN_LOG("static-ana-mod")


class StaticAnalysisParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )

    static_ana_phases: List[str] = Field(
        ["cha-0"],
        description="**Optional**, list of analysis phases to run in order. Valid values: 'cha-[0-2]' (CHA cg algo with cg level 0, 1, or 2), 'rta-[0-2]' (RTA cg algo with cg level 0, 1, or 2). Default is ['cha-0'].",
    )

    mock: bool = Field(
        False,
        description="**Optional**, whether to use mock static analysis. Default is False.",
    )

    mock_static_ana_result_dir: str = Field(
        "/eva/static-analysis/results",
        description="**Optional**, path to a mock static analysis result dir. Set when using the 'mock' analysis.",
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v

    @field_validator("static_ana_phases")
    def static_ana_phases_should_be_valid(cls, v):
        if not isinstance(v, list):
            raise ValueError("static_ana_phases must be a list")
        if not v:
            raise ValueError("static_ana_phases cannot be empty")
        valid_phases = ["cha-0", "cha-1", "cha-2", "rta-0", "rta-1", "rta-2"]
        for phase in v:
            if phase not in valid_phases:
                raise ValueError(
                    f"Invalid phase '{phase}'. Valid phases are: {valid_phases}"
                )
        return v


class DirectedFuzzTarget:
    """Directed fuzzing target."""

    def __init__(
        self,
        coord: InsnCoordinate,
        map_hash: str,
        method_list: List[str],
        target_data: Dict[str, Any],
    ):
        self.coord = coord
        self.map_hash = map_hash
        self.method_list = method_list
        self.target_data = target_data
        # Init distance map
        self.distance_map = {}
        for idx in range(len(self.method_list)):
            method = self.method_list[idx]
            distance = self.target_data["all_method_distances"][idx]
            if distance is not None and distance != "null":
                # Skip the null distance, only record reachable methods
                self.distance_map[method] = {
                    "method_distance": int(distance),
                }
        # Any reachable harnesses, map({"ana_reachable_harness_1": true, "ana_reachable_harness_2": false, ...})
        self.ana_reachability = self.target_data["target_location"].get(
            "ana_reachability", {}
        )

    @classmethod
    def frm_dict(
        cls, method_list: List[str], target_data: Dict[str, Any]
    ) -> "DirectedFuzzTarget":
        """Create a DirectedFuzzTarget from a dict."""
        coord = InsnCoordinate.frm_dict(target_data["target_location"]["coord"])
        map_hash = target_data["map_hash"]
        return cls(coord, map_hash, method_list, target_data)

    @classmethod
    async def frm_ana_rslt(
        cls, logger, ana_rslt_file: Path
    ) -> tuple[List["DirectedFuzzTarget"], List[str]]:
        """Create a list of DirectedFuzzTarget from a static analysis result file."""
        async with aiofiles.open(ana_rslt_file, "r") as f:
            content = await f.read()
            json_obj = json.loads(content)
            method_list = json_obj["all_mapped_methods"]
            targets = []
            for target_data in json_obj["target_data"]:
                try:
                    targets.append(
                        DirectedFuzzTarget.frm_dict(method_list, target_data)
                    )
                except Exception as e:
                    logger(
                        f"{CRS_ERR} parsing target location: {target_data["target_location"]}, error: {str(e)} {traceback.format_exc()}"
                    )
            return targets, method_list

    def get_target_location(self) -> Dict[str, Any]:
        """Get the target location."""
        return self.target_data["target_location"]

    def __repr__(self):
        return f"DirectedFuzzTarget(coord={self.coord}, map_hash={self.map_hash})"


class StaticAnalysis(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: StaticAnalysisParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.envs: Dict[str, str] = {}
        self.ttl_fuzz_time: int = self.crs.ttl_fuzz_time
        self.params = params
        self.enabled = self.params.enabled

        self.static_ana_phases = self.params.static_ana_phases
        self.mock = self.params.mock
        self.mock_static_ana_result_dir = self.params.mock_static_ana_result_dir
        self.workdir = self.get_workdir("") / self.crs.cp.name

        self.static_ana_jar = (
            Path(get_env_or_abort("JAVA_CRS_SRC"))
            / "static-analysis"
            / "target"
            / "static-analysis-1.0-jar-with-dependencies.jar"
        )

        self.static_ana_result = self.workdir / "static-analysis-result.json"

        self.soot_cg_file = self.workdir / "soot-cg.json"
        self.static_ana_result.parent.mkdir(parents=True, exist_ok=True)

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner: HarnessRunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner: HarnessRunner | None):
        util.TODO("Add mock result")

    def get_directed_tgt_path(self) -> Path | None:
        """Get the path for directed fuzzing targets."""
        return self.static_ana_result

    def _get_remaining_time(self) -> int:
        return max(60, int(self.crs.end_time - time.time()))

    async def _create_command_sh(
        self,
        cmd: List[str],
        script_name: str,
        working_dir: str = None,
        timeout: int = None,
        cpu_list: List[int] = None,
        buffer_output: bool = True,  # Add buffer_output parameter with default True
    ) -> Path:
        if timeout:
            cmd = ["timeout", "-s", "SIGKILL", str(timeout)] + cmd
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
{cmd_str}
"""
        command_sh = self.workdir / script_name
        async with aiofiles.open(command_sh, "w") as f_sh:
            await f_sh.write(command_sh_content)
        command_sh.chmod(0o755)
        return command_sh

    async def _gen_config_file(self, cpu_list: List[int]) -> Path:
        pkg_list = self.crs.meta.pkg_list

        classpath = set()
        for harness, data in self.crs.meta.harnesses.items():
            classpath.update(data["classpath"])

        harness_classes = set()
        for harness, data in self.crs.meta.harnesses.items():
            harness_classes.add(data["target_class"])

        self.logH(None, f"Callgraph analysis entrypoints: {len(harness_classes)}")

        config_file = self.workdir / "static-analysis-cfg.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)

        async with aiofiles.open(config_file, "w") as f:
            await f.write(
                json.dumps(
                    {
                        "cp_name": self.crs.meta.cp_name,
                        "pkg_list": sorted(pkg_list),
                        "classpath": sorted(list(classpath)),
                        "harnesses": self.crs.meta.harnesses,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )

        return config_file

    async def _update_target(self, target: DirectedFuzzTarget) -> None:
        # Update sinkmanager
        try:
            sink = Sinkpoint.frm_dict(target.get_target_location())
            self.logH(None, f"Static analysis update sinkpoint to sinkmanager: {sink}")
            await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="staticanalysis")
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} updating target {target.coord} to sinkmanager: {str(e)} {traceback.format_exc()}",
            )

    async def _process_analysis_results(self):
        """Monitor and process static analysis results."""
        last_mtime = None
        check_interval = 1

        while self.crs.should_continue():
            try:
                if not self.static_ana_result.exists():
                    await asyncio.sleep(check_interval)
                    continue

                current_mtime = self.static_ana_result.stat().st_mtime

                # Skip if file hasn't changed
                if current_mtime == last_mtime and last_mtime is not None:
                    await asyncio.sleep(check_interval)
                    continue

                self.logH(None, "Detected update to static analysis result file")

                targets, all_mapped_methods = await DirectedFuzzTarget.frm_ana_rslt(
                    lambda m: self.logH(None, m), self.static_ana_result
                )

                self.logH(
                    None, f"Parsed {len(targets)} targets from static analysis result"
                )
                for target in targets:
                    await self._update_target(target)

                last_mtime = current_mtime

            except json.JSONDecodeError:
                # File exists but isn't valid JSON yet (may be partially written)
                self.logH(
                    None,
                    "Static analysis result file exists but is not valid JSON yet, waiting...",
                )
            except Exception as e:
                self.logH(
                    None,
                    f"{CRS_ERR} parsing static analysis result: {str(e)}, traceback: {traceback.format_exc()}",
                )

            await asyncio.sleep(check_interval)

    async def _run_static_analysis(
        self, config_file: Path, cpu_list: List[int], phases: List[str]
    ):
        """Launch the static analysis tool in server mode."""
        remaining_time = self._get_remaining_time()

        self.logH(
            None,
            f"Launching static analysis in server mode with stages {phases} (timeout: {remaining_time}s)",
        )

        input_cg_paths = [
            str(self.crs.sariflistener.full_cg_file.resolve()),
            str(self.crs.llmpocgen.joern_cg_file.resolve()),
        ]

        cmd = [
            "java",
            "-jar",
            str(self.static_ana_jar.resolve()),
            "--config",
            str(config_file.resolve()),
            "--target-file",
            str(self.crs.meta.sink_target_conf.resolve()),
            "--distance-map-file",
            str(self.static_ana_result.resolve()),
            "--cg-stages",
            ",".join(phases),
            "--input-call-graphs",
            ":".join(input_cg_paths),
            "--output-call-graph",
            str(self.soot_cg_file.resolve()),
            "--cache-dir",
            get_crs_java_pod_cache_static_ana_dir(),
            "--sarif-sinkpoints",
            str(self.crs.meta.sinkpoint_path.resolve()),
            "--server",
        ]

        command_sh = await self._create_command_sh(
            cmd,
            "static-analysis-command.sh",
            timeout=remaining_time,
            cpu_list=cpu_list,
        )
        log_file = self.workdir / "static-analysis.log"

        # NOTE: A server, never exit unless killed by SIGKILL from timeout
        ret = await run_process_and_capture_output(command_sh, log_file)
        if ret in [0, 137] and self.crs.near_end():
            # killed by SIGKILL and timeout
            self.logH(
                None,
                f"Static analysis server was force ended (ret: {ret}) in {time.time() - self.crs.start_time:.2f}s",
            )
        else:
            # It is abnormal as long as we are not exit with 0 or killed by SIGKILL
            self.logH(
                None,
                f"{CRS_ERR} Static analysis server unexpectedly exits with ret {ret} in {time.time() - self.crs.start_time:.2f}s",
            )

    async def _run_mock_analysis(self):
        """Run the mock analysis phase by copying from a predefined mock file."""
        self.logH(None, "Running mock static analysis phase")

        mock_static_ana_result_file = Path(self.params.mock_static_ana_result_dir) / (
            self.crs.cp.name + "_static-analysis-result.json"
        )

        if not os.path.exists(self.mock_static_ana_result_dir):
            self.logH(
                None,
                f"{CRS_ERR} Mock file not found at {mock_static_ana_result_file}",
            )
            return

        self.logH(
            None,
            f"Copying mock result from {mock_static_ana_result_file} to {self.static_ana_result}",
        )
        self.static_ana_result.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(mock_static_ana_result_file, self.static_ana_result)

    async def _run_static_analysis_tool(self, config_file: Path, cpu_list: List[int]):
        if self.mock:
            await self._run_mock_analysis()
        else:
            await self._run_static_analysis(
                config_file, cpu_list, self.static_ana_phases
            )

    async def _distance_map_generation(self, cpu_list: List[int]):
        """Generate distance maps using static analysis tool."""
        try:
            self.logH(
                None,
                f"Enabled static analysis phases: {', '.join(self.static_ana_phases)}",
            )

            config_file = await self._gen_config_file(cpu_list)

            await asyncio.gather(
                self._run_static_analysis_tool(config_file, cpu_list),
                self._process_analysis_results(),
            )
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Static analysis failed: {str(e)}, traceback: {traceback.format_exc()}",
            )

    async def _async_run(self, _):
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled")
            return

        cpu_list = await self.crs.cpuallocator.poll_allocation(None, self.name)
        self.logH(None, f"Starting static analysis module using cores: {cpu_list}")

        try:
            await asyncio.gather(
                self._distance_map_generation(cpu_list),
            )
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} running tasks: {str(e)}, traceback: {traceback.format_exc()}",
            )
        finally:
            self.logH(
                None, f"{self.name} ended in {(time.time() - self.crs.start_time):.2f}s"
            )
