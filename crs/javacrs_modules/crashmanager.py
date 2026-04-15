#!/usr/bin/env python3
import asyncio
import os
import time
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Dict

from libCRS import CRS, Module, util
from pydantic import BaseModel, Field, field_validator

from .base_objs import Crash, InsnCoordinate, Sinkpoint
from .jazzer import Jazzer, is_fuzzing_module
from .utils import CRS_ERR_LOG, CRS_WARN_LOG, atomic_write_file_frm_path, stream_load_json
from .utils_nfs import get_oss_crs_artifact_pov_dir
from .utils_path_traversal import extract_paths_from_binary

CRS_ERR = CRS_ERR_LOG("crashmanager")
CRS_WARN = CRS_WARN_LOG("crashmanager")


class CrashManagerParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v


class CrashManager(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: CrashManagerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.envs: Dict[str, str] = {}
        self.ttl_fuzz_time: int = self.crs.ttl_fuzz_time
        self.params = params
        self.enabled = self.params.enabled

        self.processed_artifacts = defaultdict(set)
        self.processed_dedup_tokens = defaultdict(set)
        self.processed_coords = defaultdict(set)
        self.processed_exp_types = defaultdict(set)
        self.processed_frame_ids = defaultdict(set)
        self.processed_payload = defaultdict(lambda: defaultdict(set))
        self.max_payload_per_ty = 2
        self.max_frame_layer = 10
        self._submitted_result_jsons = asyncio.Queue()

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner):
        util.TODO("Add mock result")

    async def submit_new_result_json(
        self, hrunner, result_json_path: Path, mod_name: str
    ):
        """Submit a new result.json file for processing."""
        if not self.enabled:
            self.logH(
                None,
                f"Module {self.name} is disabled, skipping submission of {result_json_path}",
            )
            return

        if not result_json_path.exists():
            self.logH(
                None,
                f"{CRS_WARN} Result JSON file '{result_json_path}' does not exist, skipping submission",
            )
            return

        self.logH(
            None,
            f"Submitting new result.json file '{result_json_path}' for module '{mod_name}' and harness '{hrunner.harness.name}'",
        )

        await self._submitted_result_jsons.put((result_json_path, hrunner, mod_name))

    def _get_enabled_fuzzing_modules(self):
        return [
            mod for mod in self.crs.modules if is_fuzzing_module(mod) and mod.enabled
        ]

    def _can_skip_crash(self, hrunner, result_json_path: Path, crash: list):
        """
        What we skip:
          - malformed crash reports
          - processed crash by artifact abs path
          - processed not None dedup tokens
        """
        # crash: [time, sanitizer, crash_msg, frames, dedup_token, artifact_name]
        if len(crash) < 6:
            self.logH(
                None,
                f"{CRS_ERR} Malformed crash report with insufficient fields: {result_json_path}",
            )
            return True

        sanitizer, dedup_token, artifact_name = crash[1], crash[4], crash[5]
        harness_id = hrunner.harness.name

        if "file path traversal" not in sanitizer.lower():
            # NOTE: do not early reject file-path-traversal crashes purely based on sanitizer
            if dedup_token and dedup_token in self.processed_dedup_tokens[harness_id]:
                # Processed
                return True

        artifact_abspath = Jazzer.get_artifact_abspath(result_json_path, artifact_name)
        if artifact_abspath in self.processed_artifacts[harness_id]:
            # Processed
            return True
        if not os.path.exists(artifact_abspath):
            self.logH(
                None,
                f"{CRS_ERR} Crash artifact does not exist: {artifact_abspath} in {result_json_path}",
            )
            return True

        return False

    async def _get_unhandled_crashes(self, hrunner, result_json_path: Path):
        async for crash in stream_load_json(
            result_json_path,
            "fuzz_data.log_dedup_crash_over_time.item",
            lambda msg: self.logH(None, msg),
        ):
            if not self._can_skip_crash(hrunner, result_json_path, crash):
                yield crash

    async def _save_oss_crs_pov(self, hrunner, artifact_path: Path):
        """Save POV artifact to OSS_CRS_ARTIFACT_POV directory."""
        artifact_pov_dir = get_oss_crs_artifact_pov_dir()
        if not artifact_pov_dir:
            return

        pov_artifact_path = artifact_pov_dir / artifact_path.name
        try:
            await atomic_write_file_frm_path(pov_artifact_path, artifact_path)
            self.logH(
                None,
                f"Copied POV artifact to {pov_artifact_path}",
            )
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Failed to copy POV artifact {artifact_path} to {pov_artifact_path}: {str(e)} {traceback.format_exc()}",
            )

    async def _report_crash(
        self,
        hrunner,
        sink_coord: InsnCoordinate,
        exp_id: str,
        artifact_path: Path,
        frame_id: str,
    ):
        sanitizer_output_hash = f"{hrunner.harness.name}, {artifact_path.name}, {exp_id}, {frame_id}, {sink_coord}"
        finder = "javacrs"

        await self._save_oss_crs_pov(hrunner, artifact_path)
        await self.crs.async_submit_pov(
            hrunner.harness, artifact_path, sanitizer_output_hash, finder
        )
        self.logH(None, f"Reported new unique crash: [{sanitizer_output_hash}]")

    def _add_to_processed_sets(
        self, harness_id, sink_coord, exp_id, artifact_abspath, dedup_token, frame_id
    ):
        if sink_coord is not None:
            self.processed_coords[harness_id].add(sink_coord)
        if exp_id is not None:
            self.processed_exp_types[harness_id].add(exp_id)
        if artifact_abspath is not None:
            self.processed_artifacts[harness_id].add(artifact_abspath)
        if dedup_token is not None:
            self.processed_dedup_tokens[harness_id].add(dedup_token)
        if frame_id is not None:
            self.processed_frame_ids[harness_id].add(frame_id)

    def _get_frame_id(self, frames: list):
        return (
            ",".join(frames[: self.max_frame_layer]) if frames else "UNKNOWN-FRAME-ID"
        )

    async def _try_add_new_file_payload(
        self, harness_id: str, sanitizer: str, artifact_abspath: Path
    ) -> str | None:
        if "file path traversal" not in sanitizer.lower():
            return None
        # Only try add file payloads for file path traversal crashes
        sig = "jazzer-traversal"
        results = await extract_paths_from_binary(artifact_abspath, sig, len(sig))
        self.logH(None, f"Reporting results are: {results}")
        for ty, payload in results:
            if len(self.processed_payload[harness_id][ty]) < self.max_payload_per_ty:
                if payload not in self.processed_payload[harness_id][ty]:
                    self.processed_payload[harness_id][ty].add(payload)
                    return f"PAYLOAD:<{', '.join([ty + ':' + payload for ty, payload in results])}>"
        return None

    async def _process_crash(self, hrunner, result_json_path: Path, crash: list):
        # crash: [time, sanitizer, crash_msg, frames, dedup_token, artifact_name]
        harness_id = hrunner.harness.name
        _, sanitizer, crash_msg, frames, dedup_token, artifact_name = crash
        frame_id = self._get_frame_id(frames)
        artifact_abspath = Jazzer.get_artifact_abspath(result_json_path, artifact_name)

        sink_coord = await self.crs.sinkmanager.match_sinkpoint(frames)
        exp_id = sanitizer

        new_exp_id = exp_id not in self.processed_exp_types[harness_id]
        new_frame_id = frame_id not in self.processed_frame_ids[harness_id]
        new_file_payload = await self._try_add_new_file_payload(
            harness_id, sanitizer, artifact_abspath
        )
        non_sanitizer_crash = (
            exp_id.startswith("NONSEC-")
            or exp_id == "timeout"
            or exp_id.startswith("OOM-")
            or exp_id.startswith("StackOverflow-")
        )
        if non_sanitizer_crash:
            # timeout, OOM, StackOverflow, or uncaught exception
            do_report = new_exp_id
        else:
            # asan crash or jazzer sanitizer crash
            do_report = new_exp_id or new_frame_id or new_file_payload

        if do_report:
            self.logH(
                None,
                f"Reporting crash: {hrunner.harness.cp.name}, {hrunner.harness.name}, {artifact_name}, {frame_id}, {exp_id}, {sink_coord}, {'report' if do_report else 'not report'}, {'processed coord' if sink_coord in self.processed_coords[harness_id] else 'not processed coord'}, {'processed exp type' if exp_id in self.processed_exp_types[harness_id] else 'not processed exp type'}, 'file payload: ' {new_file_payload if new_file_payload else 'None'}",
            )
            await self._report_crash(
                hrunner, sink_coord, exp_id, Path(artifact_abspath), frame_id
            )
        else:
            self.logH(
                None,
                f"Skipping reported crash: {hrunner.harness.cp.name}, {hrunner.harness.name}, {artifact_name}, {frame_id}, {exp_id}, {sink_coord}, {'report' if do_report else 'not report'}, {'processed coord' if sink_coord in self.processed_coords[harness_id] else 'not processed coord'}, {'processed exp type' if exp_id in self.processed_exp_types[harness_id] else 'not processed exp type'}, 'file payload: ' {new_file_payload if new_file_payload else 'None'}",
            )

        self._add_to_processed_sets(
            harness_id, sink_coord, exp_id, artifact_abspath, dedup_token, frame_id
        )
        # NOTE: We don't want to mask the sinkpoint when we have a naive uncaught exception
        if not exp_id.startswith("NONSEC-") and sink_coord:
            sink = Sinkpoint.frm_crash(
                Crash(
                    hrunner.harness.name,
                    sink_coord,
                    sanitizer,
                    crash_msg,
                    frames,
                    dedup_token,
                    artifact_name,
                    artifact_abspath,
                )
            )
            self.logH(
                None, f"CrashManager update sinkpoint to sinkmanager from crash: {sink}"
            )
            await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="crashmanager")

    async def _process_result_json(self, hrunner, result_json_path: Path):
        async for crash in self._get_unhandled_crashes(hrunner, result_json_path):
            await self._process_crash(hrunner, result_json_path, crash)

    async def _collect_all_result_json_paths(self):
        """Collect all result.json paths from all harnesses and jazzer modules."""
        all_paths = []
        jazzer_mods = self._get_enabled_fuzzing_modules()

        for hrunner in self.crs.hrunners:
            for jazzer_mod in jazzer_mods:
                harness_id = hrunner.harness.name
                mod_name = jazzer_mod.name
                paths = [
                    path for path in await jazzer_mod.get_expected_result_jsons(hrunner)
                ]

                # Store tuple of (path, hrunner, jazzer_mod) for each path
                for path in paths:
                    all_paths.append((path, hrunner, mod_name))

                self.logH(
                    None,
                    f"Found {len(paths)} result.json files for module '{mod_name}' and harness '{harness_id}'",
                )

        return all_paths

    async def _check_and_process_result_json(self, path_tuple, last_mtimes):
        """Check a specific result.json file and process it if modified."""
        path, hrunner, mod_name = path_tuple
        harness_id = hrunner.harness.name

        if not path.exists():
            # Not created by fuzzer yet
            return

        try:
            current_mtime = path.stat().st_mtime

            if path not in last_mtimes:
                self.logH(
                    None,
                    f"File '{path}' for module '{mod_name}' and harness '{harness_id}' now exists, tracking for updates",
                )
                last_mtimes[path] = None

            if current_mtime != last_mtimes[path]:
                self.logH(
                    None,
                    f"Detected update to '{path}' for module '{mod_name}' and harness '{harness_id}'",
                )

                await self._process_result_json(hrunner, path)
                last_mtimes[path] = current_mtime

        except Exception as e:
            self.logH(
                None, f"{CRS_ERR} checking file '{path}': {e} {traceback.format_exc()}"
            )

    async def _monitor_all_result_jsons(self):
        """Monitor all result.json files with a simple sequential loop."""
        path_tuples = await self._collect_all_result_json_paths()
        if not path_tuples:
            self.logH(None, "No result.json files to monitor")
            return

        self.logH(None, f"Monitoring {len(path_tuples)} result.json files in total")

        last_mtimes = {}

        try:
            while True:
                for path_tuple in path_tuples:
                    await self._check_and_process_result_json(path_tuple, last_mtimes)

                while not self._submitted_result_jsons.empty():
                    try:
                        submitted_path, hrunner, mod_name = (
                            self._submitted_result_jsons.get_nowait()
                        )
                        await self._check_and_process_result_json(
                            (submitted_path, hrunner, mod_name), last_mtimes
                        )
                    except asyncio.QueueEmpty:
                        break
                    except Exception as e:
                        self.logH(
                            None,
                            f"{CRS_ERR} processing submitted result.json: {e} {traceback.format_exc()}",
                        )

                await asyncio.sleep(1)

        except asyncio.CancelledError:
            self.logH(None, "Monitoring task has been cancelled")
            raise
        except Exception as e:
            self.logH(None, f"{CRS_ERR} in monitoring loop: {e}")

    async def _async_run(self, _):
        """Monitor result.json files and handle crash reports."""
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled")
            return

        self.logH(None, f"Module {self.name} starts")

        jazzer_mods = self._get_enabled_fuzzing_modules()
        if not jazzer_mods:
            self.logH(None, "No enabled Jazzer fuzzing modules found")
            return

        monitor_task = asyncio.create_task(self._monitor_all_result_jsons())

        start_time = time.time()
        try:
            while True:
                current_time = time.time()
                elapsed_time = current_time - start_time

                if elapsed_time >= self.ttl_fuzz_time:
                    self.logH(
                        None,
                        f"Module {self.name} reached ttl_fuzz_time ({self.ttl_fuzz_time}s), cancelling monitoring task.",
                    )
                    monitor_task.cancel()
                    break

                await asyncio.sleep(1)  # Sleep before checking again
        except asyncio.CancelledError:
            self.logH(None, f"Module {self.name} has been cancelled")
            monitor_task.cancel()
        finally:
            await asyncio.gather(monitor_task, return_exceptions=True)
            self.logH(None, f"Module {self.name} has completed")
