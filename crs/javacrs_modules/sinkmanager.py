#!/usr/bin/env python3
import asyncio
import json
import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import UUID

import atomics
import redis.asyncio as redis
from libCRS import CRS, HarnessRunner, Module, util
from pydantic import BaseModel, Field, field_validator

from .base_objs import (
    BeepSeed,
    CRSJAVASarifReport,
    InsnCoordinate,
    SarifAnalysisResult,
    Sinkpoint,
)
from .utils import CRS_ERR_LOG, CRS_WARN_LOG, atomic_write_file
from .utils_redis import (
    extract_sp_key_from_hash_key,
    get_redis_sinkpoint_data_key,
    get_redis_sinkpoint_hash_key,
    get_redis_sinkpoint_hash_pattern,
    get_redis_url,
)

CRS_ERR = CRS_ERR_LOG("sinkmanager-mod")
CRS_WARN = CRS_WARN_LOG("sinkmanager-mod")


class SinkManagerParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )
    allowed_sink_contributors: List[str] = Field(
        default_factory=list,
        description=(
            "**Optional**, list of module names that are allowed to add NEW sinks "
            "to the pool. Modules not in this list can still update metadata of "
            "existing sinks but cannot introduce new ones. Empty list means all "
            "modules are allowed (backward compat). Note: Redis-synced sinks count "
            "as 'sinkmanager' source — include 'sinkmanager' here if you use "
            "multi-pod fuzzing with a non-empty allowlist."
        ),
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v


class SinkUpdateEvent:
    """Event that a sink is updated, has this event => is changed."""

    def __init__(
        self,
        coord: InsnCoordinate,
        in_prio: bool,
        reached: bool,
        exploited: bool,
        beepseeds: List[BeepSeed],
    ):
        self.coord = coord
        self.in_prio = in_prio
        self.reached = reached
        self.exploited = exploited
        self.beepseeds = beepseeds


class SinkManager(Module):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: SinkManagerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.params = params
        self.enabled = self.params.enabled
        self.allowed_sink_contributors = set(self.params.allowed_sink_contributors)
        self.ttl_fuzz_time: int = self.crs.ttl_fuzz_time
        self.workdir = self.get_workdir("") / self.crs.cp.name
        self.workdir.mkdir(parents=True, exist_ok=True)

        self._lock = asyncio.Lock()
        self.sinkpoints: Dict[InsnCoordinate, Sinkpoint] = {}
        # UUID -> CRSJAVASarifReport
        self.sarif_reports: Dict[UUID, CRSJAVASarifReport] = {}
        self.sink_redis_data: Dict[str, str] = {}  # redis_key -> JSON data
        self.sink_redis_hash: Dict[str, str] = {}  # redis_key -> hash
        # atomics to control whether to sync sinkpoints to fs
        self._should_sync_sinks_to_fs = atomics.atomic(width=4, atype=atomics.INT)
        self.sink_conf_path = Path(self.workdir / "custom-sinkpoints.conf")

        # Redis connection
        self.redis = None

    def _init(self):
        pass

    async def _async_prepare(self):
        pass

    async def _async_test(self, hrunner: HarnessRunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner: HarnessRunner | None):
        util.TODO("Add mock result")

    def get_custom_sink_conf_path(self) -> Path:
        """Get the path to the custom sink configuration file."""
        return self.sink_conf_path

    async def _init_redis(self):
        """Initialize Redis connection."""
        start_time = time.time()
        try:
            if self.redis is not None:
                await self.redis.ping()
                return

            redis_url = get_redis_url()
            self.redis = redis.from_url(redis_url, decode_responses=True)
            await self.redis.ping()
            duration = time.time() - start_time
        except Exception as e:
            duration = time.time() - start_time
            if self.redis is not None:
                self.logH(
                    None,
                    f"{CRS_ERR} Existing conn failed after {duration:.2f}s, will reconnect: {e} {traceback.format_exc()}",
                )
            else:
                self.logH(
                    None,
                    f"{CRS_ERR} Failed to init conn after {duration:.2f}s: {e} {traceback.format_exc()}",
                )
            self.redis = None

    async def _get_sink_from_redis(self, sp_key: str) -> Optional[Sinkpoint]:
        """Get Sinkpoint object from Redis."""
        try:
            sp_data_key = get_redis_sinkpoint_data_key(sp_key)
            sp_data = await self.redis.get(sp_data_key)
            if not sp_data:
                return None

            sp_dict = json.loads(sp_data)
            return Sinkpoint.frm_dict(sp_dict)
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} Getting sinkpoint from Redis for {sp_key}: {e}\n{traceback.format_exc()}",
            )
            return None

    async def _get_redis_sp_hashes(self) -> Dict[str, str]:
        try:
            # Use scan to get all hash keys
            pattern = get_redis_sinkpoint_hash_pattern()
            keys = []
            cursor = 0

            while True:
                cursor, results = await self.redis.scan(
                    cursor=cursor, match=pattern, count=1000
                )
                keys.extend(results)
                if cursor == 0:
                    break

            if not keys:
                return {}

            sp_hashes = {}
            async with self.redis.pipeline() as pipeline:
                for sp_hash_key in keys:
                    pipeline.get(sp_hash_key)

                results = await pipeline.execute()
                for i, hash_value in enumerate(results):
                    if hash_value:
                        sp_key = extract_sp_key_from_hash_key(keys[i])
                        sp_hashes[sp_key] = hash_value
            return sp_hashes

        except Exception as e:
            self.logH(
                None,
                f"SYNC-2 {CRS_ERR} Failed to get sinkpoint hashes: {e} {traceback.format_exc()}",
            )
            return {}

    async def _get_local_sp_keys(self) -> set[str]:
        """Get all local sp_keys."""
        local_keys = set()
        async with self._lock:
            for sp in self.sinkpoints.values():
                local_keys.add(sp.redis_key())
        return local_keys

    async def _get_local_sp_data_and_hash(
        self, sp_key: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Get local sinkpoint data and hash for a given sp_key."""
        async with self._lock:
            return self.sink_redis_data.get(sp_key), self.sink_redis_hash.get(sp_key)

    async def _pull_sinkpoint_from_redis(self, sp_key: str):
        sinkpoint = await self._get_sink_from_redis(sp_key)
        if sinkpoint is None:
            return
        await self.on_event_update_sinkpoint(sinkpoint, source="sinkmanager")

    async def _push_sinkpoint_to_redis(
        self, sp_key: str, remote_hash: Optional[str]
    ) -> bool:
        local_data, local_hash = await self._get_local_sp_data_and_hash(sp_key)
        if local_data is None:
            self.logH(None, f"SYNC-4 No local data for {sp_key}, skipping push")
            return False

        try:
            async with self.redis.pipeline(transaction=True) as tr:
                sp_hash_key = get_redis_sinkpoint_hash_key(sp_key)
                await tr.watch(sp_hash_key)

                current_hash = await self.redis.get(sp_hash_key)
                if current_hash != remote_hash:
                    await tr.unwatch()
                    return False

                # Update Redis
                sp_data_key = get_redis_sinkpoint_data_key(sp_key)
                tr.multi()
                tr.set(sp_data_key, local_data)
                tr.set(sp_hash_key, local_hash)
                await tr.execute()
                return True

        except redis.WatchError:
            self.logH(
                None, f"SYNC-4 Concurrent modification for {sp_key}, skipping push"
            )
            return False
        except Exception as e:
            self.logH(
                None,
                f"SYNC-4 {CRS_ERR} Failed to push {sp_key}: {e} {traceback.format_exc()}",
            )
            return False

    async def _sync_single_sinkpoint(self, sp_key: str, remote_hash: Optional[str]):
        """Sync a single sinkpoint between local and Redis."""
        try:
            _, local_hash = await self._get_local_sp_data_and_hash(sp_key)
            if (remote_hash is not None) and (
                local_hash is None or local_hash != remote_hash
            ):
                await self._pull_sinkpoint_from_redis(sp_key)

            _, local_hash = await self._get_local_sp_data_and_hash(sp_key)
            if local_hash is not None and (
                remote_hash is None or local_hash != remote_hash
            ):
                await self._push_sinkpoint_to_redis(sp_key, remote_hash)

        except Exception as e:
            self.logH(None, f"SYNC-4 {CRS_ERR} {sp_key}: {e} {traceback.format_exc()}")
            return

    async def _sync_with_redis(self):
        """Sync sinkpoints with Redis at sinkpoint granularity."""
        sync_period = 60
        cur_count = 0
        while self.crs.should_continue():
            if cur_count < sync_period:
                cur_count += 1
                await asyncio.sleep(1)
                continue
            else:
                cur_count = 0

            try:
                step_start = time.time()
                await self._init_redis()
                step_duration = time.time() - step_start

                if self.redis is None:
                    self.logH(
                        None,
                        f"SYNC-1 SKIPPED: Redis connection not available ({step_duration:.2f}s)",
                    )
                    continue

                sync_start_time = time.time()
                self.logH(None, "SYNC-1 Beginning Redis sync")

                step_start = time.time()
                remote_sp_hashes = await self._get_redis_sp_hashes()
                step_duration = time.time() - step_start
                self.logH(
                    None,
                    f"SYNC-2 Found {len(remote_sp_hashes)} sinkpoints in Redis ({step_duration:.2f}s)",
                )

                step_start = time.time()
                local_sp_keys = await self._get_local_sp_keys()
                step_duration = time.time() - step_start
                self.logH(
                    None,
                    f"SYNC-3 Found {len(local_sp_keys)} local sinkpoints ({step_duration:.2f}s)",
                )

                all_sp_keys = set(remote_sp_hashes.keys()) | local_sp_keys
                step_start = time.time()
                for sp_key in all_sp_keys:
                    await self._sync_single_sinkpoint(
                        sp_key, remote_sp_hashes.get(sp_key)
                    )

                step_duration = time.time() - step_start
                self.logH(
                    None,
                    f"SYNC-4 Synced {len(all_sp_keys)} sinkpoints in Redis ({step_duration:.2f}s)",
                )

                sync_duration = time.time() - sync_start_time
                self.logH(
                    None,
                    f"SYNC-5 Redis sync completed in {sync_duration:.2f} seconds",
                )

            except Exception as e:
                self.logH(
                    None,
                    f"SYNC-ERROR: {CRS_ERR} sync sink with Redis: {e} {traceback.format_exc()}",
                )

        self.logH(None, "Reached end time, exiting _sync_with_redis")

    async def _dump_to_sinkpoint_path(self):
        """Dump sinkpoints to self.crs.meta.sinkpoint_path."""
        try:
            async with self._lock:
                json_obj = [s.to_dict() for s in self.sinkpoints.values()]
            json_ctnt = json.dumps(json_obj, indent=2)
            await atomic_write_file(self.crs.meta.sinkpoint_path, json_ctnt)
            self.logH(None, f"Dumped sinkpoints to {self.crs.meta.sinkpoint_path}")
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in dumping sinks to file: {str(e)} {traceback.format_exc()}",
            )

    async def _dump_to_sink_conf_path(self):
        """Dump sinkpoints to self.sink_conf_path."""
        try:
            async with self._lock:
                confs = [sink.coord.to_conf() for sink in self.sinkpoints.values()]
                confs = [conf for conf in confs if conf]
                # Each line ends with '\n', including the last one. POSIX-correct
                # text file; lets readers like `wc -l` count sinks accurately.
                conf_ctnt = "".join(f"{c}\n" for c in confs)
            await atomic_write_file(self.sink_conf_path, conf_ctnt)
            self.logH(None, f"Dumped sinkpoints to {self.sink_conf_path}")
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in dumping sinks to conf file: {str(e)} {traceback.format_exc()}",
            )

    async def _sync_sinkpoints_to_fs(self):
        """Sync sinkpoints path to self.crs.meta.sinkpoint_path."""
        self.logH(None, "Starting sinkpoints sync to filesystem")
        sync_period = 60
        cur_count = 0
        while self.crs.should_continue():
            cur_count += 1
            if cur_count >= sync_period:
                self._should_sync_sinks_to_fs.store(1)

            if self._should_sync_sinks_to_fs.load() != 0:
                self._should_sync_sinks_to_fs.store(0)

                await self._dump_to_sinkpoint_path()
                await self._dump_to_sink_conf_path()
                cur_count = 0

            await asyncio.sleep(1)
        self.logH(None, "Reached end time, exiting _sync_sinkpoints_to_fs")

    def _is_contributor_allowed(self, source: str) -> bool:
        """Check if a source module is allowed to add new sinks."""
        # Empty allowlist means all sources allowed (backward compat)
        if not self.allowed_sink_contributors:
            return True
        return source in self.allowed_sink_contributors

    async def _update_sink(
        self, sink: Sinkpoint, source: str
    ) -> List[SinkUpdateEvent]:
        async with self._lock:
            updated_sink = None

            # Update sink obj
            if sink.coord not in self.sinkpoints:
                # New sink: enforce contributor allowlist
                if not self._is_contributor_allowed(source):
                    self.logH(
                        None,
                        f"Dropping new sink {sink.coord} from '{source}' (not in allowlist {sorted(self.allowed_sink_contributors)})",
                    )
                    return []
                self.sinkpoints[sink.coord] = sink
                updated_sink = sink
            else:
                # Existing sink: metadata updates always allowed
                if self.sinkpoints[sink.coord].merge(sink):
                    updated_sink = self.sinkpoints[sink.coord]

            if updated_sink is None:
                # Nothing changed
                return []

            # Update self.sarif_reports
            updated_sarifs = []
            for report in updated_sink.sarif_reports.values():
                if report.sarif_id in self.sarif_reports:
                    cur_report = self.sarif_reports[report.sarif_id]
                    if cur_report.merge(report):
                        updated_sarifs.append(cur_report.sarif_id)
                else:
                    self.sarif_reports[report.sarif_id] = report
                    updated_sarifs.append(report.sarif_id)

            # NOTE: Completely link all sinks to all report again is too costly,
            #       so we check updated sink & updated sarif_reports
            # For updated sink
            for sarif_id in self.sarif_reports:
                if sarif_id not in updated_sink.sarif_reports:
                    updated_sink.mark_as_sarif_target_if_should(
                        lambda m: self.logH(None, m), self.sarif_reports[sarif_id]
                    )

            # For updated sarif reports
            updated_coords = {updated_sink.coord}
            for sarif_id in updated_sarifs:
                report = self.sarif_reports[sarif_id]
                for sp in self.sinkpoints.values():
                    if sp.mark_as_sarif_target_if_should(
                        lambda m: self.logH(None, m), report
                    ):
                        updated_coords.add(sp.coord)

            events = []
            for coord in updated_coords:
                sp = self.sinkpoints[coord]
                if coord == updated_sink.coord:
                    # If this is the updated sink, we need to update its beepseeds
                    beepseeds = [bs for bs in sp.beepseeds]
                else:
                    beepseeds = []
                events.append(
                    SinkUpdateEvent(
                        coord=sp.coord,
                        in_prio=sp.in_prio(),
                        reached=sp.reached(),
                        exploited=sp.exploited(),
                        beepseeds=beepseeds,
                    )
                )
                # Update redis data
                redis_key = sp.redis_key()
                data, hash_val = sp.data_n_hash()
                self.sink_redis_data[redis_key] = data
                self.sink_redis_hash[redis_key] = hash_val

            return events

    async def _update_sarif_report(
        self, result: SarifAnalysisResult
    ) -> List[SinkUpdateEvent]:
        """Update SARIF report and return the coordinates of sinkpoints."""
        async with self._lock:
            updated = False

            if result.sarif_id in self.sarif_reports:
                cur_report = self.sarif_reports[result.sarif_id]
                updated = cur_report.add_result(result)
            else:
                cur_report = CRSJAVASarifReport.frm_results([result], solved=False)
                self.sarif_reports[result.sarif_id] = cur_report
                updated = True

            if not updated:
                return []
            events = []
            for sp in self.sinkpoints.values():
                if sp.mark_as_sarif_target_if_should(
                    lambda m: self.logH(None, m), cur_report
                ):
                    events.append(
                        SinkUpdateEvent(
                            coord=sp.coord,
                            in_prio=sp.in_prio(),
                            reached=sp.reached(),
                            exploited=sp.exploited(),
                            beepseeds=[],
                        )
                    )
                    # Update redis data
                    redis_key = sp.redis_key()
                    data, hash_val = sp.data_n_hash()
                    self.sink_redis_data[redis_key] = data
                    self.sink_redis_hash[redis_key] = hash_val
            return events

    async def _mark_sarif_report_as_solved(
        self, sarif_id: UUID
    ) -> List[SinkUpdateEvent]:
        """Mark a SARIF report as solved and return the coordinates of sinkpoints."""
        async with self._lock:
            if sarif_id not in self.sarif_reports:
                self.logH(
                    None, f"{CRS_WARN} SARIF report {sarif_id} does not exist, skipping"
                )
                return []

            cur_report = self.sarif_reports[sarif_id]
            if cur_report.is_solved():
                return []

            cur_report.mark_as_solved()
            events = []
            for sp in self.sinkpoints.values():
                if sp.mark_as_sarif_target_if_should(
                    lambda m: self.logH(None, m), cur_report
                ):
                    events.append(
                        SinkUpdateEvent(
                            coord=sp.coord,
                            in_prio=sp.in_prio(),
                            reached=sp.reached(),
                            exploited=sp.exploited(),
                            beepseeds=[],
                        )
                    )
                    # Update redis data
                    redis_key = sp.redis_key()
                    data, hash_val = sp.data_n_hash()
                    self.sink_redis_data[redis_key] = data
                    self.sink_redis_hash[redis_key] = hash_val
            return events

    async def _notify_sink_update_events(
        self, label: str, events: List[SinkUpdateEvent]
    ):
        """Notify other modules about sink updates."""
        if len(events) == 0:
            return

        n_in_prio = sum(1 for e in events if e.in_prio)
        n_reached = sum(1 for e in events if e.reached)
        n_exp = sum(1 for e in events if e.exploited)
        n_sink = len(events)
        self.logH(
            None,
            f"{label}: in_prio={n_in_prio}, reached={n_reached}, exped={n_exp}, total={n_sink}",
        )

        # In-process notification: expkit, concolic, etc
        await self.crs.expkit.on_event_update_coord_info(events)
        await self.crs.concolic.on_event_update_coord_info(events)
        # Fs-based notification: static-analysis, llmpocgen, etc
        self._should_sync_sinks_to_fs.store(1)

    async def on_event_new_sarif_challenge(self, result: SarifAnalysisResult):
        """Add new SARIF result."""
        if not self.enabled:
            self.logH(
                None, f"Module {self.name} is disabled, skip handling the SARIF result"
            )
            return

        try:
            events = await self._update_sarif_report(result)
            await self._notify_sink_update_events("NEW-SARIF-EVENT", events)
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in on_event_new_sarif_challenge: {str(e)} {traceback.format_exc()}",
            )

    async def on_event_sarif_challenge_solved(self, sarif_id: UUID):
        """Mark a SARIF result as solved."""
        if not self.enabled:
            self.logH(
                None,
                f"Module {self.name} is disabled, skip marking the SARIF result as solved",
            )
            return

        try:
            events = await self._mark_sarif_report_as_solved(sarif_id)
            await self._notify_sink_update_events("SARIF-SOLVED-EVENT", events)
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in on_event_sarif_challenge_solved: {str(e)} {traceback.format_exc()}",
            )

    async def on_event_update_sinkpoint(self, sink: Sinkpoint, source: str):
        """Handle new sinkpoint.

        Args:
            sink: The Sinkpoint to add or merge.
            source: Name of the calling module (e.g. 'sinkdetection', 'crashmanager').
                    Used to enforce the `allowed_sink_contributors` allowlist for new
                    sinks. Existing sinks always accept metadata updates regardless.
        """
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled, skip sink update event")
            return

        try:
            events = await self._update_sink(sink, source)
            await self._notify_sink_update_events("SINK-UPDATE-EVENT", events)
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in on_event_update_sinkpoint: {str(e)} {traceback.format_exc()}",
            )

    async def match_sinkpoint(self, frames: list[str]) -> InsnCoordinate | None:
        # NOTE: used by crashmanager, this might be slow when there are too many sinkpoints
        if not self.enabled:
            # self.logH(None, f"Module {self.name} is disabled, skip matching sinkpoint from crash frames")
            return None

        try:
            async with self._lock:
                coords = set(self.sinkpoints.keys())

            # TODO: @cen, this is a bit slow, we can optimize it, and what if there are multiple sinkpoints should be matched?
            for coord in coords:
                if coord.is_in_stack_frames(frames):
                    return coord
        except Exception as e:
            self.logH(
                None, f"{CRS_ERR} in match_sinkpoint: {str(e)} {traceback.format_exc()}"
            )
        return None

    async def format_manager_stats(self) -> str:
        """Format sink manager stats for display."""
        try:
            async with self._lock:
                n_sinkpoints = len(self.sinkpoints)
                n_sarif_reports = len(self.sarif_reports)
                stats = f"Sink Manager: {self.name}, Sinkpoints: {n_sinkpoints}, SARIF Reports: {n_sarif_reports}"
                # detailed status, how many sinkpoints are in prio, reached, exploited
                n_in_prio = sum(
                    1 for sinkpoint in self.sinkpoints.values() if sinkpoint.in_prio()
                )
                n_reached = sum(
                    1 for sinkpoint in self.sinkpoints.values() if sinkpoint.reached()
                )
                n_exploited = sum(
                    1 for sinkpoint in self.sinkpoints.values() if sinkpoint.exploited()
                )
                stats += f", In Prio: {n_in_prio}, Reached: {n_reached}, Exploited: {n_exploited}"
                # detailed status, how many sinkpoints are linked to sarif reports
                n_sarif_linked = sum(
                    1
                    for sinkpoint in self.sinkpoints.values()
                    if len(sinkpoint.sarif_reports) > 0
                )
                stats += f", SARIF Linked: {n_sarif_linked}"
                # print every sinkpoint
                stats += "\nSinkpoints:\n"
                for sinkpoint in self.sinkpoints.values():
                    stats += f"{sinkpoint}\n"
                return stats
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} in format_manager_stats: {str(e)} {traceback.format_exc()}",
            )
            return f"{CRS_ERR} in formatting manager stats"

    async def _log_dump_stats(self):
        """Log dump stats every 1800 seconds."""
        count = 0
        while self.crs.should_continue():
            try:
                if count % 1800 == 0:
                    stats = await self.format_manager_stats()
                    self.logH(None, stats)
            except Exception as e:
                self.logH(
                    None,
                    f"{CRS_ERR} in _log_dump_stats: {str(e)} {traceback.format_exc()}",
                )
            finally:
                await asyncio.sleep(1)
                count += 1

        self.logH(None, "Reached end time, exiting _log_dump_stats")

    async def _async_run(self, _):
        if not self.enabled:
            self.logH(None, f"Module {self.name} is disabled")
            return

        cpu_list = await self.crs.cpuallocator.poll_allocation(None, self.name)
        self.logH(None, f"Starting sink manager module using cores: {cpu_list}")

        try:
            await asyncio.gather(
                self._sync_with_redis(),
                self._sync_sinkpoints_to_fs(),
                self._log_dump_stats(),
            )
        except Exception as e:
            self.logH(
                None,
                f"{CRS_ERR} sinkmanager failed: {str(e)}, traceback: {traceback.format_exc()}",
            )
        finally:
            self.logH(None, f"Sink manager module {self.name} finished")
