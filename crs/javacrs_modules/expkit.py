#!/usr/bin/env python3
import asyncio
import json
import os
import random
import shlex
import time
import traceback
import uuid
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import List, Optional, Set

import aiofiles
from libCRS import CRS, HarnessRunner, Module, util
from pydantic import BaseModel, Field, field_validator

from .base_objs import BeepSeed, InsnCoordinate, Sinkpoint
from .dictgen import BEEPSeedDictGenReq
from .jazzer import is_beep_mode_on, is_fuzzing_module
from .sinkmanager import SinkUpdateEvent
from .utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    get_env_exports,
    run_process_and_capture_output,
)

XCODE_FILE = "xcode.json"
CRS_ERR = CRS_ERR_LOG("expkit-mod")
CRS_WARN = CRS_WARN_LOG("expkit-mod")


class ExpKitParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )
    exp_time: int = Field(
        300,
        description="**Optional**, timeout in seconds for each beepseed exploitation. Default is 300 seconds.",
    )
    gen_model: str = Field(
        ...,
        description="**Mandatory**, LLM model used by the exploitation agent.",
    )
    debug_list_txt: Optional[str] = Field(
        None,
        description="**Optional**, path to debug list txt file where each line is a beepseed file location. If specified, expkit will load beepseeds from this list instead of monitoring directories.",
    )
    schedule_count: int = Field(
        -1,
        description="**Optional**, how many times each beepseed should be scheduled. -1 means infinite (default), 0 or positive values set the limit.",
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v

    @field_validator("exp_time")
    def exp_time_should_be_positive(cls, v):
        if v <= 0:
            raise ValueError("exp_time must be a positive integer")
        return v

    @field_validator("gen_model")
    def gen_model_should_be_non_empty(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("gen_model must be a non-empty string")
        return v

    @field_validator("debug_list_txt")
    def debug_list_txt_should_be_valid(cls, v):
        if v is not None and not isinstance(v, str):
            raise ValueError("debug_list_txt must be a string path or None")
        return v

    @field_validator("schedule_count")
    def schedule_count_should_be_valid(cls, v):
        if not isinstance(v, int) or v < -1:
            raise ValueError("schedule_count must be an integer >= -1")
        return v


class BeepSeedScheduler:
    """
    Concurrency-safe exploitation scheduler for observed BeepSeeds.

    Two-layer scheduling strategy:
    1. Pick the least explored coordinate that is not masked (enabled)
    2. For that coordinate, pick the least explored context
    3. Randomly pick a BeepSeed with the chosen coordinate and context
    """

    def __init__(self, schedule_count: int = -1):
        # {coord -> (ttl_sched_cnt, {stack_hash -> (sched_cnt, set([beepseeds]))})}
        self.queues = {}
        # in prio (sarif/diff)
        self.prio_coords = set()
        # exploited
        self.exp_coords = set()
        self.lock = asyncio.Lock()
        self.target_harnesses = set()
        # schedule_count: -1 = infinite, 0+ = limit per beepseed
        self.schedule_count = schedule_count
        # track individual beepseed scheduling counts: {beepseed -> count}
        self.beepseed_sched_counts = {}

    def add_target_harnesses(self, target_harnesses: List[str]):
        """Add target harnesses to the scheduler."""
        # NOTE: not safe in concurrent environment, expect to be called only once
        self.target_harnesses.update(target_harnesses)

    async def add(self, beepseed: BeepSeed) -> bool:
        """Add a beepseed to the queue. Return True if it is a new beepseed."""
        if beepseed.target_harness not in self.target_harnesses:
            return False  # Ignore beepseeds for non-target harnesses
        async with self.lock:
            is_new = False
            if beepseed.coord not in self.queues:
                self.queues[beepseed.coord] = (0, {})

            _, contexts = self.queues[beepseed.coord]
            if beepseed.stack_hash not in contexts:
                # New exec stack context
                contexts[beepseed.stack_hash] = (0, {beepseed})
                is_new = True
            else:
                _, beepseeds = contexts[beepseed.stack_hash]
                if beepseed not in beepseeds:
                    # New datasha1
                    beepseeds.add(beepseed)
                    is_new = True

            return is_new

    async def next(self) -> Optional[BeepSeed]:
        """Get next beepseed using two-layer scheduling strategy. None -> no beepseed available."""
        async with self.lock:
            # Clean up beepseeds that have reached their schedule limit
            if self.schedule_count >= 0:
                self._cleanup_exhausted_beepseeds()

            unexp_coords = set(self.queues.keys()) - self.exp_coords
            if not unexp_coords:
                return None
            unexp_prio_coords = unexp_coords.intersection(self.prio_coords)
            unexp_nonprio_coords = unexp_coords - unexp_prio_coords

            # Do prio coord scheduling or non-prio
            if len(unexp_prio_coords) > 0 and random.random() < 0.5:
                picked_coords = unexp_prio_coords
            else:
                picked_coords = unexp_nonprio_coords

            # Do schedule
            least_sched_coord = min(picked_coords, key=lambda c: self.queues[c][0])
            ttl_cnt, contexts = self.queues[least_sched_coord]

            least_sched_ctxt = min(contexts, key=lambda c: contexts[c][0])
            ctxt_cnt, beepseeds = contexts[least_sched_ctxt]

            if len(beepseeds) == 0:
                # NOTE: This should not happen
                return None

            # Filter beepseeds that haven't reached their schedule limit
            if self.schedule_count >= 0:
                available_beepseeds = [
                    bs
                    for bs in beepseeds
                    if self.beepseed_sched_counts.get(bs, 0) < self.schedule_count
                ]
                if not available_beepseeds:
                    # All beepseeds in this context have reached their limit
                    # Remove them and try again
                    beepseeds.clear()
                    return await self.next()
            else:
                available_beepseeds = list(beepseeds)

            # TODO: this may be inefficient if len > 1k, but will that happen?
            beepseed = random.choice(available_beepseeds)

            # Update scheduling counts
            self.beepseed_sched_counts[beepseed] = (
                self.beepseed_sched_counts.get(beepseed, 0) + 1
            )

            # Update stats
            contexts[least_sched_ctxt] = (ctxt_cnt + 1, beepseeds)
            self.queues[least_sched_coord] = (ttl_cnt + 1, contexts)

            return beepseed

    def _cleanup_exhausted_beepseeds(self):
        """Remove beepseeds that have reached their schedule limit from the queues."""
        for coord, (ttl_cnt, contexts) in self.queues.items():
            for stack_hash, (sched_cnt, beepseeds) in contexts.items():
                exhausted_beepseeds = {
                    bs
                    for bs in beepseeds
                    if self.beepseed_sched_counts.get(bs, 0) >= self.schedule_count
                }
                beepseeds -= exhausted_beepseeds

    async def set_coord_priority(self, coord: InsnCoordinate, new_prio: bool) -> bool:
        """Set the coordinate as prio or not. Return True if it is changed."""
        async with self.lock:
            old_prio = coord in self.prio_coords
            if new_prio:
                self.prio_coords.add(coord)
            else:
                self.prio_coords.discard(coord)
            return old_prio != new_prio

    async def add_exp_coord(self, coord: InsnCoordinate) -> bool:
        """Remove the coordinate from the queue, which can be caused by exploited/dropped/.. Return True if it is newly masked."""
        async with self.lock:
            not_exist = coord not in self.exp_coords
            if not_exist:
                self.exp_coords.add(coord)
        return not_exist

    async def format_scheduler_status(self) -> str:
        """Format the status of all coordinates."""
        format_str = "ExpKit Scheduler Status:\n"
        format_str += f" - prio coords: {len(self.prio_coords)}\n"
        format_str += f" - exploited coords: {len(self.exp_coords)}\n"
        format_str += f" - total coords: {len(self.queues)}\n"
        async with self.lock:
            for coord, (ttl_sched_cnt, detail) in self.queues.items():
                ttl_beepseed_cnt = 0
                for _, (_, beepseeds) in detail.items():
                    ttl_beepseed_cnt += len(beepseeds)
                format_str += f" - Coord: {coord}, Sched Count: {ttl_sched_cnt}, {len(detail)} stack_hashs, {ttl_beepseed_cnt} beepseeds\n"
                for context, (sched_cnt, beepseeds) in detail.items():
                    format_str += f"   - Stack Hash: {context}, Sched Count: {sched_cnt}, Beepseed Count: {len(beepseeds)}\n"
                    # for beepseed in beepseeds:
                    #    format_str += f"     - Beepseed: {beepseed}\n"
        return format_str


class ExpKit(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: ExpKitParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.workdir = self.get_workdir(self.crs.cp.name)
        self.ttl_fuzz_time: int = self.crs.ttl_fuzz_time
        self.params = params
        self.enabled = self.params.enabled
        self.monitor_interval = 0.1
        self.exp_time = self.params.exp_time
        self.gen_model = self.params.gen_model
        self.handled_beeps: Set[str] = set()
        # NOTE: This should be init in runtime, in async_run
        self.target_harnesses: List[str] | None = None
        self.beepseed_scheduler = BeepSeedScheduler(self.params.schedule_count)
        # NOTE: this is for fast match crash frames with reached sinkpoint coords
        self.reached_sink_lock = asyncio.Lock()
        self.reached_sink_coords = set()
        self.cpu_list = []

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner: HarnessRunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner: Optional[HarnessRunner]):
        util.TODO("Add mock result")

    async def _get_all_beepseed_dirs(self):
        beep_jazzer_mods = [mod for mod in self.crs.modules if is_beep_mode_on(mod)]

        if not beep_jazzer_mods:
            self.logH(None, "Jazzer modules with beep mode enabled not found")
            return []

        self.logH(
            None, f"Found {len(beep_jazzer_mods)} beep jazzer mods: {beep_jazzer_mods}"
        )

        all_beepseed_dirs = []
        for hrunner in self.crs.hrunners:
            for mod in beep_jazzer_mods:
                beepseed_dirs = await mod.get_expected_beepseed_dir(hrunner)
                for beepseed_dir in beepseed_dirs:
                    # N.B. Fuzzer may not be ready now, guarantee dir existence
                    beepseed_dir.parent.mkdir(parents=True, exist_ok=True)
                    all_beepseed_dirs.append(beepseed_dir)

        self.logH(
            None, f"Found {len(all_beepseed_dirs)} beepseed dirs: {all_beepseed_dirs}"
        )
        return all_beepseed_dirs

    async def _is_handled_path(self, path: Path) -> bool:
        # NOTE: Add lock when beepseed is collected in parallel
        return str(path.resolve()) in self.handled_beeps

    async def _mark_handled_path(self, path: Path):
        # NOTE: Add lock when beepseed is collected in parallel
        self.handled_beeps.add(str(path.resolve()))

    async def _set_coord_prio(self, coord: InsnCoordinate, in_prio: bool):
        changed = await self.beepseed_scheduler.set_coord_priority(coord, in_prio)
        if changed:
            self.logH(
                None,
                f"Coord {coord} prio has changed to {in_prio} in beepseed scheduler",
            )
            if self.crs.verbose:
                self.logH(
                    None, f"{await self.beepseed_scheduler.format_scheduler_status()}"
                )

    async def _set_coord_exploited(self, coord: InsnCoordinate):
        is_new = await self.beepseed_scheduler.add_exp_coord(coord)
        if is_new:
            self.logH(
                None, f"Coord {coord} is set as exploited, will not be in schedule"
            )
            self.logH(
                None, f"{await self.beepseed_scheduler.format_scheduler_status()}"
            )

    async def on_event_update_coord_info(self, events: List[SinkUpdateEvent]):
        """NOTE: Called by sinkmanager to update the status of a coordinate."""
        if not self.enabled:
            return

        for event in events:
            await self._set_coord_prio(event.coord, event.in_prio)
            if event.exploited is True:
                await self._set_coord_exploited(event.coord)
            # Currently this module does not care event.reached
            for bs in event.beepseeds:
                if bs.target_harness in self.target_harnesses:
                    await self.beepseed_scheduler.add(bs)

    async def _collect_new_beepseeds_in_dir(self, beepseed_dir: Path):
        if not beepseed_dir.exists():
            return

        async def is_unprocessed_beepseed(entry: Path) -> bool:
            global XCODE_FILE
            return (
                entry.is_file()
                and not entry.name.startswith(".")
                and entry.suffix.lower() == ".json"
                # Skip xcode.json, a metadata file instead of a beepseed
                and entry.name != XCODE_FILE
                and not await self._is_handled_path(entry)
            )

        async def process_beepseed(json_path: Path):
            self.logH(None, f"Processing beepseed {json_path}")

            try:
                beepseed = await BeepSeed.frm_beep_file(json_path)
                if beepseed.is_empty_data():
                    self.logH(
                        None,
                        f"Skip beepseed {json_path} with empty input data {beepseed.data_hex_str}",
                    )
                else:
                    await self.beepseed_scheduler.add(beepseed)

                sink = Sinkpoint.frm_beepseed(beepseed)
                self.logH(
                    None,
                    f"Expkit update sinkpoint to sinkmanager from beepseed: {sink}",
                )
                await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="expkit")

                # Mark after it is successfully handled as race can happen when loading
                await self._mark_handled_path(json_path)

            except (FileNotFoundError, JSONDecodeError) as e:
                self.logH(None, f"Try again later for beepseed {json_path}")
                if self.crs.verbose:
                    self.logH(
                        None, f"{CRS_WARN} Error processing beepseed {json_path}: {e}"
                    )
                    self.logH(None, f"{traceback.format_exc()}")

            except Exception as e:
                self.logH(
                    None,
                    f"{CRS_ERR} Unexpected error processing beepseed {json_path}: {e}",
                )
                self.logH(None, f"{traceback.format_exc()}")

        try:
            for entry in beepseed_dir.iterdir():
                if await is_unprocessed_beepseed(entry):
                    await process_beepseed(entry)

        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Unexpected error iterating beepseed_dir {beepseed_dir}: {e}",
            )
            self.logH(None, f"{traceback.format_exc()}")

    async def _load_debug_beepseeds_from_list(self, debug_list_txt: str):
        """Load beepseeds from debug list txt file (one-time, not monitoring)."""
        debug_list_path = Path(debug_list_txt)
        if not debug_list_path.exists():
            self.logH(None, f"{CRS_ERR} Debug list file not found: {debug_list_txt}")
            return

        try:
            async with aiofiles.open(debug_list_path, "r") as f:
                lines = await f.readlines()

            beepseed_paths = [Path(line.strip()) for line in lines if line.strip()]
            self.logH(
                None,
                f"Loading {len(beepseed_paths)} beepseeds from debug list {debug_list_txt}",
            )

            for beepseed_path in beepseed_paths:
                if not beepseed_path.exists():
                    self.logH(
                        None,
                        f"{CRS_WARN} Debug beepseed file not found: {beepseed_path}",
                    )
                    continue

                if not beepseed_path.suffix.lower() == ".json":
                    self.logH(
                        None,
                        f"{CRS_WARN} Debug beepseed file not a JSON: {beepseed_path}",
                    )
                    continue

                await self._process_debug_beepseed(beepseed_path)

        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Error loading debug beepseeds from {debug_list_txt}: {e}",
            )
            self.logH(None, f"{traceback.format_exc()}")

    async def _process_debug_beepseed(self, json_path: Path):
        """Process a single debug beepseed file."""
        self.logH(None, f"Processing debug beepseed {json_path}")

        try:
            beepseed = await BeepSeed.frm_beep_file(json_path)
            if beepseed.is_empty_data():
                self.logH(
                    None,
                    f"Skip debug beepseed {json_path} with empty input data {beepseed.data_hex_str}",
                )
            else:
                await self.beepseed_scheduler.add(beepseed)

            sink = Sinkpoint.frm_beepseed(beepseed)
            self.logH(
                None,
                f"Expkit update sinkpoint to sinkmanager from debug beepseed: {sink}",
            )
            await self.crs.sinkmanager.on_event_update_sinkpoint(sink, source="expkit")

        except (FileNotFoundError, JSONDecodeError) as e:
            self.logH(
                None, f"{CRS_ERR} Error processing debug beepseed {json_path}: {e}"
            )
            self.logH(None, f"{traceback.format_exc()}")
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Unexpected error processing debug beepseed {json_path}: {e}",
            )
            self.logH(None, f"{traceback.format_exc()}")

    async def _gen_exploit_script(
        self,
        beepseed_file: Path,
        output_dir: Path,
        cpu_id: int,
        result_file: Path,
        log_file: Path,
        exp_time: int,
        time_left: int,
    ) -> Path:
        """Generate shell script to execute expkit tool for a beepseed."""
        command = [
            "timeout",
            "-s",
            "SIGKILL",
            f"{str(time_left)}s",
            "taskset",
            "-c",
            str(cpu_id),
            "python3.12",
            "-m",
            "expkit.exploit",
            str(beepseed_file.resolve()),
            str(result_file.resolve()),
            "--metadata",
            str(self.crs.meta.meta_path.resolve()),
            "--exp-time",
            str(exp_time),
            "--gen-model",
            self.gen_model,
            "--workdir",
            str(output_dir.resolve()),
            "--verbose",
        ]

        command_str = " ".join(shlex.quote(str(arg)) for arg in command)
        command_sh_content = f"""#!/bin/bash
# Environment variables
{get_env_exports(os.environ)}
# Command
{command_str} > "{log_file.resolve()}" 2>&1
"""

        command_sh = output_dir / "command.sh"
        async with aiofiles.open(command_sh, "w") as f:
            await f.write(command_sh_content)
        command_sh.chmod(0o755)

        return command_sh

    async def _handle_result_file(
        self, beepseed: BeepSeed, result_file: Path, exploit_dir: Path
    ) -> bool:
        """Process exploitation result file and copy corpus files to fuzzer corpus directories."""
        try:
            if not result_file.exists():
                self.logH(None, f"Result file not created at {result_file}")
                return False

            async with aiofiles.open(result_file, "r") as f:
                result_json = json.loads(await f.read())

            status_result = result_json.get("status", False)
            self.logH(
                None,
                f"Exp {'successful' if status_result else 'unsuccessful'} for {beepseed}",
            )
            if not status_result:
                self.logH(
                    None,
                    f"INFO: {result_json.get('error', 'Not exploit successfully.')}",
                )

            workdir = result_json.get("workdir", None)
            if not workdir:
                self.logH(None, f"{CRS_ERR} No workdir in result file {result_file}")
                return status_result
            target_harness = beepseed.target_harness
            if not target_harness:
                self.logH(None, f"{CRS_ERR} No target_harness in beepseed {beepseed}")
                return status_result

            harness_class_name = target_harness.split(".")[-1]
            matching_hrunner = next(
                (
                    hr
                    for hr in self.crs.hrunners
                    if hr.harness.name == harness_class_name
                ),
                None,
            )
            if not matching_hrunner:
                self.logH(
                    None,
                    f"{CRS_ERR} No matching harness runner found for {harness_class_name}",
                )
                return status_result

            jazzer_mods = [
                mod
                for mod in self.crs.modules
                if mod.enabled and is_fuzzing_module(mod)
            ]
            if not jazzer_mods:
                self.logH(
                    None,
                    f"{CRS_ERR} No enabled Jazzer modules found for copying corpus",
                )
                return status_result

            corpus_dir = Path(workdir) / "corpus_dir"
            # Broadcast generated poc
            poc_file = corpus_dir / "poc"
            if poc_file.exists() and poc_file.is_file():
                self.logH(
                    None, f"Sharing generated poc file {poc_file} to all jazzer modules"
                )
                for mod in jazzer_mods:
                    await mod.add_corpus_file(matching_hrunner, poc_file)

            # Share corpus files
            if corpus_dir.exists() and corpus_dir.is_dir():
                self.logH(
                    None,
                    f"Sharing corpus files from {corpus_dir} to fuzzers' corpus_dir",
                )
                for corpus_file in corpus_dir.iterdir():
                    if corpus_file.is_file():
                        await self.crs.seedsharer.add_seed_to_queue(
                            matching_hrunner, self.name, corpus_file
                        )

            # Share result.json for findings
            fuzz_result = result_json.get("results_json", None)
            if fuzz_result and os.path.exists(fuzz_result):
                self.logH(
                    None,
                    f"Sharing fuzz result file {fuzz_result} to fuzzers' corpus_dir",
                )
                await self.crs.crashmanager.submit_new_result_json(
                    matching_hrunner, Path(fuzz_result), self.name
                )

            return status_result

        except Exception as e:
            self.logH(None, f"{CRS_ERR} handling result file: {e}")
            self.logH(None, f"{traceback.format_exc()}")
            return False

    async def _exploit_one_beepseed(
        self, beepseed: BeepSeed, cpu_id: int, elapsed_time: int
    ) -> bool:
        try:
            actual_exp_time = min(self.exp_time, int(self.ttl_fuzz_time - elapsed_time))
            if actual_exp_time <= 10:
                self.logH(
                    None,
                    f"No enough time for exploitation, skipping beepseed {beepseed}",
                )
                return False

            self.logH(None, f"Processing beepseed: {beepseed} on CPU {cpu_id}")

            exploit_dir = (
                self.workdir / f"exp-{beepseed.data_sha1[:8]}-{uuid.uuid4().hex[:8]}"
            )
            exploit_dir.mkdir(parents=True, exist_ok=True)

            beepseed_file = exploit_dir / "beepseed.json"
            result_file = exploit_dir / "exp.json"
            log_file = exploit_dir / "exploit.log"
            dict_file = exploit_dir / "fuzz.dict"

            async with aiofiles.open(beepseed_file, "w") as f:
                await f.write(json.dumps(beepseed.json_obj, indent=2))

            self.logH(
                None,
                f"Requesting dictionary generation for beepseed {beepseed.data_sha1[:8]}",
            )
            await self.crs.dictgen.request_dict_gen(
                harness_name=beepseed.target_harness,
                target_dict_path=dict_file,
                dict_gen_reqs=[BEEPSeedDictGenReq(beep_seed=beepseed)],
            )

            exploit_script = await self._gen_exploit_script(
                beepseed_file,
                exploit_dir,
                cpu_id,
                result_file,
                log_file,
                actual_exp_time,
                int(self.ttl_fuzz_time - elapsed_time),
            )

            self.logH(None, f"Starting exploitation with timeout {actual_exp_time}s")
            self.logH(
                None,
                f"Running exploit for beepseed {beepseed.data_sha1[:8]} on CPU {cpu_id}...",
            )
            ret = await run_process_and_capture_output(
                exploit_script, exploit_dir / "run.log"
            )
            if ret in [0, 137] and not self.crs.should_continue():
                self.logH(None, f"Exp instance was killed with return code {ret}")
            else:
                self.logH(
                    None, f"Exp instance unexpectedly exited with return code {ret}"
                )

            return await self._handle_result_file(beepseed, result_file, exploit_dir)

        except Exception as e:
            self.logH(None, f"{CRS_ERR} in exp task for beepseed {beepseed}: {e}")
            self.logH(None, f"{traceback.format_exc()}")
            return False

    async def _exploitation_worker(self, cpu_id: int, debug_mode: bool = False):
        self.logH(
            None,
            f"Exploitation worker on CPU {cpu_id} started (debug_mode={debug_mode})",
        )
        start_time = time.time()
        elapsed_time = time.time() - start_time

        while elapsed_time < self.ttl_fuzz_time:
            beepseed = await self.beepseed_scheduler.next()
            if beepseed is not None:
                succ = await self._exploit_one_beepseed(beepseed, cpu_id, elapsed_time)
                if succ:
                    await self._set_coord_exploited(beepseed.coord)
            elif debug_mode:
                # In debug mode, if scheduler returns None, exit the worker
                self.logH(
                    None,
                    f"Exploitation worker on CPU {cpu_id} exiting (no more beepseeds in debug mode)",
                )
                break

            await asyncio.sleep(1)
            elapsed_time = time.time() - start_time
        self.logH(None, f"Exploitation worker on CPU {cpu_id} completed")

    async def _async_run(self, _):
        """Exploitation fuzzing phase on collected beepseeds."""
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled")
            return

        self.cpu_list = await self.crs.cpuallocator.poll_allocation(None, self.name)
        if self.cpu_list is None:
            self.logH(None, "No CPU allocated, skipping")
            return

        # Check if debug mode is enabled
        debug_mode = self.params.debug_list_txt is not None

        if debug_mode:
            self.logH(
                None,
                f"Module {self.name} starts in DEBUG MODE, CPU cores: {self.cpu_list}, debug_list_txt: {self.params.debug_list_txt}, schedule_count: {self.params.schedule_count}",
            )
        else:
            all_beepseed_dirs = await self._get_all_beepseed_dirs()
            if not all_beepseed_dirs:
                self.logH(
                    None, "No beepseed directories found for any module, skipping"
                )
                return

            self.logH(
                None,
                f"Module {self.name} starts in NORMAL MODE, CPU cores: {self.cpu_list}, {len(all_beepseed_dirs)} beepseed dirs",
            )

        self.target_harnesses = self.crs.get_target_harnesses()
        self.beepseed_scheduler.add_target_harnesses(self.target_harnesses)
        self.logH(None, f"Init target harnesses for expkit: {self.target_harnesses}")

        try:
            start_time = time.time()

            # Load beepseeds based on mode
            if debug_mode:
                # Debug mode: load beepseeds from debug list txt (one-time)
                await self._load_debug_beepseeds_from_list(self.params.debug_list_txt)
            # Normal mode: beepseeds will be loaded in monitoring loop

            exp_workers = [
                asyncio.create_task(self._exploitation_worker(cpu_id, debug_mode))
                for cpu_id in self.cpu_list
            ]

            if debug_mode:
                # Debug mode: no monitoring loop, just wait for workers to finish
                self.logH(None, "Debug mode: waiting for workers to complete")
                await asyncio.gather(*exp_workers)
            else:
                # Normal mode: monitoring loop
                while time.time() - start_time < self.ttl_fuzz_time:
                    for beepseed_dir in all_beepseed_dirs:
                        await self._collect_new_beepseeds_in_dir(beepseed_dir)

                    await asyncio.sleep(self.monitor_interval)

                self.logH(
                    None,
                    f"Module {self.name} stops monitoring {len(all_beepseed_dirs)} beepseed dirs after ({self.ttl_fuzz_time}s)",
                )

                await asyncio.gather(*exp_workers)

        except Exception as e:
            self.logH(None, f"{CRS_ERR} in exploit kit module: {e}")
            self.logH(None, f"{traceback.format_exc()}")

        finally:
            self.logH(
                None, f"{await self.beepseed_scheduler.format_scheduler_status()}"
            )
            self.logH(None, "Exploit kit module completed")
