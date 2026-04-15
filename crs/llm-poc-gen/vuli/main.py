import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

from vuli.blackboard import Blackboard
from vuli.chatlog import ChatLog
from vuli.commandline import CommandLineOption, CommandLineOptionBuilder
from vuli.common.setting import Setting
from vuli.cp import CP
from vuli.delta import (
    DeltaManager,
    DeltaReachableAnalyzer,
    LLMDeltaHandler,
    SinkManagerDeltaHandler,
)
from vuli.dev import Dev
from vuli.query_loader import QueryLoader
from vuli.runner import Runner, create_runner


def initialize_system(
    cp_meta: Path,
    jazzer: Optional[Path],
    joern_dir: Path,
    output_dir: Path,
    dev: bool,
    harnesses: list[str],
    query: str,
    cg_paths: list[Path],
    dump_report: bool,
    server_dir: Optional[Path],
    shared_dir: Optional[Path],
    diff_threashold: int,
) -> None:
    root_dir: Path = Path(__file__).parent.parent.absolute()
    Setting().load(jazzer, joern_dir, output_dir, root_dir, dev, shared_dir)
    ChatLog().initialize(Setting().output_dir)
    asyncio.run(Blackboard().set_path(Setting().blackboard_path))
    CP().load(cp_meta, harnesses, cg_paths)
    CP()._server_dir = server_dir
    Dev().load(Setting().root_dir / "eval" / "sheet" / "cpv.toml")

    if QueryLoader().load(Path(__file__).parent.parent / "queries" / query) is False:
        raise RuntimeError(f"Failed to load Query [path={query}]")

    if dump_report is True:
        Setting().path_path = Setting().output_dir / "path.json"

    DeltaManager().add(
        DeltaReachableAnalyzer(),
        SinkManagerDeltaHandler(),
        LLMDeltaHandler(threashold=diff_threashold),
    )


def initialize_logger(log_level: str, otel: bool) -> None:
    # if otel is True:
    #     from libCRS.otel import install_otel_logger

    #     install_otel_logger(action_name="crs-java:llm-poc-gen")

    level = getattr(logging, log_level, None)
    if level is None:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(name)s] (%(levelname)s) %(message)s",
        handlers=[logging.StreamHandler()],
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("anthropic._base_client").setLevel(logging.CRITICAL)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("openai._base_client").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore.connection").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore.http11").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3.connection").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)
    logging.getLogger("aiosqlite").setLevel(logging.CRITICAL)


def main():
    cmd_option: Optional[CommandLineOption] = CommandLineOptionBuilder().build()
    if cmd_option is None:
        return

    initialize_logger(cmd_option.log_level, cmd_option.mode == "crs")
    logger = logging.getLogger("main")

    initialize_system(
        cmd_option.cp_meta,
        cmd_option.jazzer,
        cmd_option.joern,
        cmd_option.output_dir,
        cmd_option.is_dev,
        cmd_option.harnesses,
        cmd_option.query,
        cmd_option.cg_paths,
        cmd_option.dump_report,
        cmd_option.server_dir,
        cmd_option.shared_dir,
        cmd_option.diff_threashold,
    )
    runner: Optional[Runner] = create_runner(
        cmd_option.mode, cmd_option.workers, cmd_option.model_cache,
        cmd_option.models, cmd_option.scan_sinks,
    )
    if runner is None:
        logger.error(f"Not Found Runner [mode={cmd_option.mode}]")
        return
    asyncio.run(runner.run())


if __name__ == "__main__":
    sys.exit(main())
