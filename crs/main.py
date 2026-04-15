#!/usr/bin/env python3
import asyncio
import logging
import sys
import time
import traceback
from pathlib import Path
from typing import List

from coordinates import BytecodeInspector, CodeCoordinate
from cpmetadata import JavaCPMetadata, javacrs_init_cp
from javacrs_modules import (
    AIxCCJazzer,
    AtlDirectedJazzer,
    AtlJazzer,
    AtlLibAFLJazzer,
    SinkDetection,
    ConcolicExecutor,
    CPUAllocator,
    CrashManager,
    DeepGenModule,
    Dictgen,
    DiffScheduler,
    ExpKit,
    LLMFuzzAugmentor,
    LLMPOCGenerator,
    SARIFListener,
    SeedMerger,
    SeedSharer,
    SinkManager,
    StaticAnalysis,
)
from javacrs_modules.utils import CRS_ERR_LOG, CRS_WARN_LOG
from javacrs_modules.utils_e2echeck import e2e_check_loop
from javacrs_modules.utils_leader import LeaderElectionManager
from javacrscfg import JavaCRSParams, load_javacrs_cfg
from libCRS import CRS
from libCRS import Config as libCRSConfig
from libCRS import HarnessRunner, Module

CRS_ERR = CRS_ERR_LOG("main")
CRS_WARN = CRS_WARN_LOG("main")


try:
    from libCRS.otel import install_otel_logger

    install_otel_logger(action_name="crs-java:main")
except Exception as e:
    print(f"{CRS_WARN} Failed to install OpenTelemetry logger: {e}.")


class JavaHR(HarnessRunner):
    """HarnessRunner for Java CPs"""

    async def async_run(self):
        tasks = [
            self.crs.aixccjazzer.async_run(self),
            self.crs.atljazzer.async_run(self),
            self.crs.atldirectedjazzer.async_run(self),
            self.crs.atllibafljazzer.async_run(self),
            self.crs.seedmerger.async_run(self),
            self.crs.llmfuzzaug.async_run(self),
            self.crs.concolic.async_run(self),
        ]
        task_objs = [asyncio.create_task(task) for task in tasks]

        await asyncio.gather(*task_objs)


class JavaCRS(CRS):
    def __init__(self, name: str, hr_cls: type[HarnessRunner], conf_file: Path):
        self.params: JavaCRSParams = load_javacrs_cfg(conf_file)
        self.ttl_fuzz_time = self.params.ttl_fuzz_time
        self.verbose = self.params.verbose
        self.e2e_check = self.params.e2e_check
        self.sync_log = self.params.sync_log
        self.ssmode = self.params.ssmode
        self.hrunners = []

        self.start_time = int(time.time())
        self.end_time = self.start_time + self.ttl_fuzz_time

        super().__init__(
            name,
            hr_cls,
            libCRSConfig(node_idx=0, node_cnt=1).load(conf_file),
            javacrs_init_cp(),
            Path(self.params.workdir) if self.params.workdir else None,
        )

        self.meta = JavaCPMetadata(self)
        self.leader_election = LeaderElectionManager()
        if self.sinkmanager.params.enabled:
            self.inspector = BytecodeInspector(
                self.get_workdir("coordinates") / self.cp.name
            )
            self.inspector.init_mapping(
                list(self.meta.pkg2files.keys()), self.meta.get_merged_classpath()
            )
        else:
            self.inspector = None

    def _init_modules(self) -> List[Module]:
        module_list = [
            # cp level modules
            ("cpuallocator", CPUAllocator, False),
            ("seedsharer", SeedSharer, False),
            ("crashmanager", CrashManager, False),
            ("llmpocgen", LLMPOCGenerator, False),
            ("staticanalysis", StaticAnalysis, False),
            ("sinkmanager", SinkManager, False),
            ("expkit", ExpKit, False),
            ("sariflistener", SARIFListener, False),
            ("deepgen", DeepGenModule, False),
            ("dictgen", Dictgen, False),
            ("diff_scheduler", DiffScheduler, False),
            ("sinkdetection", SinkDetection, False),
            # per-harness modules
            ("concolic", ConcolicExecutor, True),
            ("aixccjazzer", AIxCCJazzer, True),
            ("atljazzer", AtlJazzer, True),
            ("atldirectedjazzer", AtlDirectedJazzer, True),
            ("atllibafljazzer", AtlLibAFLJazzer, True),
            ("seedmerger", SeedMerger, True),
            ("llmfuzzaug", LLMFuzzAugmentor, True),
        ]
        # arg: name, crs, params, run_per_harness
        return [
            clz(name, self, getattr(self.params.modules, name), run_per_harness)
            for name, clz, run_per_harness in module_list
        ]

    async def _async_prepare(self):
        self.log("Prepare")
        await self.async_prepare_modules()

    async def _async_watchdog(self):
        """Add sth keep monitoring the CRS at here (if needed)."""
        leader_task = asyncio.create_task(
            self.leader_election.run_leader_election(self.should_continue)
        )

        e2e_check_workdir = self.get_workdir("e2echeck") / self.cp.name
        e2e_task = asyncio.create_task(
            e2e_check_loop(
                self,
                self.e2e_check,
                self.sync_log,
                self.should_continue,
                self.log,
                e2e_check_workdir,
            )
        )

        try:
            await asyncio.gather(leader_task, e2e_task)
        except Exception as e:
            self.log(f"Error in watchdog tasks: {str(e)} {traceback.format_exc()}")

    def is_leader(self) -> bool:
        """Check if this crs instance is the leader."""
        return self.leader_election.is_leader()

    async def async_wait_for_leader(self, timeout: int) -> bool:
        """Wait until this instance becomes a leader or timeout occurs: True/False => leader/timeout."""
        if self.is_leader():
            return True

        if timeout < 0:
            wait_end_time = self.end_time
        else:
            wait_end_time = min(int(time.time()) + timeout, self.end_time)

        while not self.is_leader():
            if time.time() >= wait_end_time:
                return False
            await asyncio.sleep(10)
        return True

    def should_continue(self) -> bool:
        """Check if the CRS should continue running based on the end time."""
        return time.time() < self.end_time

    def rest_time(self) -> int:
        """Get the remaining time for the CRS to run."""
        return max(0, int(self.end_time - time.time()))

    def near_end(self) -> bool:
        # NOTE: just an empirical value for helping some logging
        return self.end_time - time.time() < 30

    def is_ssmode(self) -> bool:
        """Check if ssmode is enabled."""
        return self.ssmode

    def query_code_coord(self, classname: str, linenum: int) -> CodeCoordinate | None:
        """Get the bytecode location from the source code line number."""
        return self.inspector.query(classname, linenum) if self.inspector else None

    def get_target_harnesses(self) -> List[str]:
        """Get the target harnesses from the configuration."""
        harnesses = [h.harness.name for h in self.hrunners]
        if not harnesses:
            self.log(
                f"{CRS_ERR} No target harnesses specified, this means either config error or this func is called in wrong context."
            )
        return harnesses

    async def main(self):
        """JavaCRS entry func."""
        self.log("JavaCRS starts")

        tasks = [
            # cp-level crs modules: harness runner arg is None
            self.cpuallocator.async_run(None),
            self.seedsharer.async_run(None),
            self.crashmanager.async_run(None),
            self.llmpocgen.async_run(None),
            self.staticanalysis.async_run(None),
            self.sinkmanager.async_run(None),
            self.expkit.async_run(None),
            self.sariflistener.async_run(None),
            self.deepgen.async_run(None),
            self.dictgen.async_run(None),
            self.diff_scheduler.async_run(None),
            self.sinkdetection.async_run(None),
            # libCRS entry func: inits harness runners and harness-level crs modules
            self.async_run(False),
        ]
        task_objs = [asyncio.create_task(task) for task in tasks]

        await asyncio.gather(*task_objs)

        return 0


def javaCRS_main(argv):
    conf = Path(argv[1])
    crs = JavaCRS("JavaCRS", JavaHR, conf)
    return asyncio.run(crs.main())


if __name__ == "__main__":
    try:
        exit_status = javaCRS_main(sys.argv)
    except Exception as e:
        logging.error(f"{CRS_ERR} Fatal Error:\n {e}")
        traceback.print_exc()
        exit_status = 2
    exit(exit_status)
