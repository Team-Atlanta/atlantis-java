import asyncio
import logging
import os
import pickle
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from langchain_core.caches import BaseCache
from langchain_openai import ChatOpenAI

from vuli import path_manager
from vuli.blackboard import Blackboard, BlackboardDataStatus
from vuli.calltree import CallTree
from vuli.common.decorators import SEVERITY, async_safe, step
from vuli.common.setting import Setting
from vuli.cp import CP
from vuli.delta import (  # LLMDeltaHandler,
    DeltaManager,
    DeltaReachableAnalyzer,
    SinkManagerDeltaHandler,
)
from vuli.joern import CPG, Joern
from vuli.model_manager import DBCache, ModelManager, MultiCache, RedisCache
from vuli.models import get_model
from vuli.path_manager import PathManager
from vuli.pathfinder import FindPathService
from vuli.reflection import ReflectionSolver
from vuli.resume import Resume
from vuli.scanner import Scanner
from vuli.sink import SinkManager
from vuli.sinkupdateservice import JavaCRS, SarifUpdateTask, SinkUpdateService
from vuli.struct import VulInfo
from vuli.task import (
    BlobGeneration,
    CoverageBasedGeneration,
    OneTimeGeneration,
    SyncCallGraph,
    TaskManager,
)


class Runner(ABC):
    def __init__(self):
        self._logger = logging.getLogger("Runner")

    @abstractmethod
    async def _run(self) -> None:
        pass

    async def run(self) -> None:
        start_time = time.time()
        try:
            harnesses: list[str] = self._get_harnesses()
            if len(harnesses) == 0:
                return

            self._logger.info(f"Harnesses: {','.join(harnesses)}")

            if not await self._initialize_joern():
                return

            if not await self._initialize_calltree(harnesses):
                return

            await self._run()

            await self._save_output(start_time)
        finally:
            await Joern().close_server()

    @step([], SEVERITY.ERROR, "Runner")
    def _get_harnesses(self):
        harness_names: list[str] = CP().get_harness_names()
        if len(harness_names) == 0:
            raise RuntimeError("Harness Not Found")
        return harness_names

    @async_safe(False, SEVERITY.ERROR, "Runner")
    async def _initialize_joern(self) -> bool:
        cpg: CPG = CPG(Setting().cpg_path)
        if not cpg.path.exists():
            if Setting().calltree_db_path.exists():
                os.unlink(Setting().calltree_db_path)
            exclude_dirs: list[Path] = []
            await cpg.build(
                Path(Setting().joern_javasrc_path),
                Path(CP().source_dir),
                exclude_dirs,
                CP().get_dependent_jars(),
            )

        self._logger.info("Run Joern Server")
        Joern().set_path(Setting().joern_cli_path)
        if not await Joern().run_server(
            cpg, Setting().query_path, Setting().semantic_dir
        ):
            raise RuntimeError("Failed to run Joern Server")

        return True

    @async_safe(False, SEVERITY.ERROR, "Runner")
    async def _initialize_calltree(self, harnesses: list[str]) -> bool:
        await CallTree().set_path(Setting().calltree_db_path)
        await CallTree().build(harnesses)
        return True

    @step(None, SEVERITY.ERROR, "Runner")
    async def _save_output(self, start_time: time.time) -> None:
        running_time: time.time = time.time() - start_time
        await Blackboard().set_time(running_time)

        for key, status in PathManager()._table.items():
            vul_info: VulInfo = pickle.loads(key)
            Blackboard_status: BlackboardDataStatus = BlackboardDataStatus.NOT_REACHED
            if status == path_manager.Status.REACHABLE:
                Blackboard_status = BlackboardDataStatus.REACHED
            elif status == path_manager.Status.EXPLOITABLE:
                Blackboard_status = BlackboardDataStatus.EXPLOITED
            await Blackboard().add_path(
                vul_info.harness_id,
                vul_info.v_paths,
                list(await SinkManager().get_bug_types(vul_info.sink_id)),
                Blackboard_status,
            )
        await Blackboard().save()
        self._logger.info(f"LLM Usage:\n{ModelManager().print_total_usage()}")


class StandAlone(Runner):
    def __init__(self, workers: int = 1, scan_sinks: bool = True):
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        self._blobgen = BlobGeneration(CoverageBasedGeneration(), workers)
        self._scan_sinks = scan_sinks

    async def _run(self) -> None:
        if self._scan_sinks:
            await Scanner().run(CP().sanitizers)
        await DeltaManager().handle()
        # await ReflectionSolver(CP().get_harnesses()).run()
        await FindPathService()._run()
        self._blobgen._stop = True
        await self._blobgen.run()


class CRS(Runner):
    def __init__(self, workers: int = 1, scan_sinks: bool = True):
        super().__init__()
        self._logger = logging.getLogger("CRS")
        self._scan_sinks = scan_sinks
        sink_updater = SinkUpdateService()
        sink_updater.add_task(JavaCRS(CP()._sink_path))
        TaskManager().add_handlers(
            BlobGeneration(CoverageBasedGeneration(), workers),
            FindPathService(),
            sink_updater,
            SyncCallGraph(),
            ReflectionSolver(CP().get_harnesses()),
        )

        try:
            if CP()._server_dir is not None:
                resume = Resume(
                    CP()._server_dir,
                    [
                        Setting().calltree_db_path.name,
                        Setting().cpg_path.name,
                        Setting().model_cache_path.name,
                    ],
                )
                asyncio.run(resume.download())
                TaskManager().add_handlers(resume)
            else:
                self._logger.info("Server directory is not set")
        except Exception as e:
            self._logger.warning(
                f"Failed to synchronize Server directory [reason={e.__class__.__name__}: {e}]"
            )

    async def _run(self) -> None:
        TaskManager()._stop = False
        if self._scan_sinks:
            await Scanner().run(CP().sanitizers)
        await DeltaManager().handle()

        self._logger.info(
            f"Tasks: {",".join(x.__class__.__name__ for x in TaskManager()._handlers)}"
        )
        await TaskManager().run()


class C_SARIF(Runner):

    def __init__(self, workers: int = 1):
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        self._blobgen = BlobGeneration(OneTimeGeneration(), workers)

    async def _run(self):
        await SarifUpdateTask(CP()._sink_path).run()
        await SyncCallGraph()._run()
        await FindPathService()._run()
        self._blobgen._stop = True
        await self._blobgen.run()


class STATIC(Runner):
    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        TaskManager().clear()
        TaskManager().add_handlers(
            FindPathService(),
            JavaCRS(CP()._sink_path),
            SyncCallGraph(),
            # ReflectionSolver(CP().get_harnesses()),
        )

        DeltaManager().clear()
        DeltaManager().add(
            DeltaReachableAnalyzer(),
            SinkManagerDeltaHandler(),
            # LLMDeltaHandler(),
        )

    async def _run(self):
        await Scanner().run(CP().sanitizers)
        # await ReflectionSolver(CP().get_harnesses()).run()
        await DeltaManager().handle()
        await FindPathService()._run()
        if Setting().path_path is not None:
            await PathManager().summary(Setting().path_path)


class SINK(Runner):
    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

    async def _run(self):
        await Scanner().run(CP().sanitizers)


def create_runner(
    mode: str,
    workers: int = 1,
    model_cache: Optional[Path] = None,
    models: Optional[list[str]] = None,
    scan_sinks: bool = True,
) -> Optional[Runner]:
    model_map = {
        "onetime": ["claude-sonnet-4-20250514", "o3", "gemini-2.5-pro", "gpt-4.1"],
        "c_sarif": ["gemini-2.5-pro", "gpt-4.1"],
        "static": ["gemini-2.5-pro", "gpt-4.1", "claude-sonnet-4-20250514"],
        "sink": ["gemini-2.5-pro", "gpt-4.1", "claude-sonnet-4-20250514"],
        "default": [
            "claude-opus-4-20250514",
            "o3",
            "claude-sonnet-4-20250514",
            "gemini-2.5-pro",
            "gpt-4.1",
        ],
    }

    runner_map = {
        "onetime": lambda: StandAlone(workers, scan_sinks),
        "static": STATIC,
        "sink": SINK,
        "c_sarif": lambda: C_SARIF(workers),
        "default": lambda: CRS(workers, scan_sinks),
    }

    if models is None:
        models = model_map.get(mode, model_map["default"])

    runner_factory = runner_map.get(mode, runner_map["default"])

    set_models(model_cache, models)
    return runner_factory()


def set_models(model_cache: Optional[Path], models: list[str]):
    api_key: str = os.getenv("LITELLM_KEY", "tmp")
    base_url: str = os.getenv(
        "AIXCC_LITELLM_HOSTNAME",
        "https://litellm-proxy-153298433405.us-east1.run.app",
    )
    temperature: float = 1.0
    if model_cache is not None:
        shutil.copy(model_cache, Setting().model_cache_path)

    # Model Cache
    caches: list[BaseCache] = []
    redis_url: str = os.getenv("CPMETA_REDIS_URL", None)
    try:
        if redis_url is not None:
            redis_cache = RedisCache(redis_url)
            caches.append(redis_cache)
    except Exception as e:
        logging.getLogger("main").warning(
            f"Redis Model Cache Initialize Fail [exc={e.__class__.__name__}: {e}]"
        )
    try:
        caches.append(DBCache(Setting().model_cache_path))
    except Exception as e:
        logging.getLogger("main").warning(
            f"Local DB Model Cache Fail [exc={e.__class__.__name__}: {e}]"
        )

    if len(caches) > 0:
        asyncio.run(ModelManager().set_cache(MultiCache(caches)))
    else:
        logging.getLogger("main").warning("Failed to set cache for LLM")
    asyncio.run(ModelManager().set_max_retries(3))

    for name in models:
        model = get_model(name)
        if not model:
            continue
        model = model()

        asyncio.run(
            ModelManager().add_model(
                lambda input, output: model.cost(input, output),
                name,
                ChatOpenAI(
                    api_key=api_key,
                    base_url=base_url,
                    model=model.name,
                    temperature=temperature,
                    timeout=180,
                ),
            )
        )
