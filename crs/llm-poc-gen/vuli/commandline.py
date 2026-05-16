import logging
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class CommandLineOption(BaseModel):
    cp_meta: Path
    jazzer: Optional[Path] = None
    joern: Path
    query: Path
    model_cache: Optional[Path] = None
    output_dir: Path
    harnesses: list[str]
    is_dev: bool
    dump_report: bool
    log_level: str
    cg_paths: list[Path]
    workers: int
    mode: str
    server_dir: Optional[Path] = None
    shared_dir: Optional[Path] = None
    diff_threashold: int
    models: Optional[list[str]] = None
    scan_sinks: bool = True


class CommandLineOptionBuilder:
    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)

    def build(self) -> Optional[CommandLineOption]:
        parser = ArgumentParser(description="llm-poc-gen")
        parser.add_argument(
            "--cp_meta",
            required=True,
            type=str,
            help="CP metadata file (required)",
        )
        parser.add_argument("--dev", action="store_true", help="Dev Mode")
        parser.add_argument(
            "--harnesses",
            type=str,
            help="This option allows you to specify the IDs of the harnesses you want to test. If you want to test multiple harnesses, you can list their IDs separated by commas. If this option is not provided, the test will be performed on all available harnesses.",
        )
        parser.add_argument(
            "--jazzer", required=False, type=str, help="The path to jazzer"
        )
        parser.add_argument(
            "--joern_dir",
            required=True,
            type=str,
            help="The path to the Joern directory",
        )
        parser.add_argument(
            "--log_level",
            choices=["DEBUG", "INFO", "WARN", "ERROR"],
            default="INFO",
            type=str,
            help="Log Level[DEBUG/INFO/WARN/ERROR](default: INFO)",
        )
        parser.add_argument(
            "--model_cache", type=str, help="The path to cache for model interaction"
        )
        parser.add_argument(
            "--workers",
            default=1,
            type=int,
            help="The number of workers for blob generation",
        )
        parser.add_argument(
            "--output_dir",
            default=str(Path("output").absolute()),
            type=str,
            help="The path to the output directory",
        )
        parser.add_argument(
            "--query",
            default="java.yaml",
            type=str,
            help="The name of the query[default=java.yaml]",
        )
        parser.add_argument(
            "--mode",
            default="crs",
            type=str,
            choices=["crs", "onetime", "c_sarif", "static", "sink"],
            help="Run Mode",
        )
        parser.add_argument("--cg", default="", type=str, help="Call Graph Input Path")
        parser.add_argument(
            "--report", action="store_true", help="Save Generation Info"
        )
        parser.add_argument(
            "--server_dir",
            type=str,
            help="The path to the server directory that store/download files to resume",
        )
        parser.add_argument(
            "--shared_dir",
            required=False,
            type=str,
            help="The path to share generated seeds",
        )
        parser.add_argument(
            "--diff_threashold",
            type=int,
            default=-1,
            help="Threshold for an LLM to attempt diff file analysis",
        )
        parser.add_argument(
            "--models",
            type=str,
            default=None,
            help="Comma-separated list of available LLM model names. If not set, uses mode-specific defaults.",
        )
        parser.add_argument(
            "--scan-sinks",
            action="store_true",
            default=False,
            help="Enable Joern-based sink discovery (FROM_INSIDE). If not set, relies solely on CRS sinkmanager sinks.",
        )
        args = parser.parse_args()

        cp_meta: Path = Path(args.cp_meta).absolute()
        joern: Path = Path(args.joern_dir).absolute()
        query: Path = (Path(__file__).parent.parent / "queries" / args.query).absolute()
        jazzer: Optional[Path] = (
            Path(args.jazzer).absolute() if args.jazzer else None
        )
        model_cache: Optional[Path] = (
            Path(args.model_cache).absolute() if args.model_cache else None
        )
        shared: Optional[Path] = (
            Path(args.shared_dir).absolute() if args.shared_dir else None
        )

        not_exist_paths: list[Path] = [
            x
            for x in [cp_meta, jazzer, joern, query, model_cache]
            if x is not None and not x.exists()
        ]
        if len(not_exist_paths) > 0:
            self._logger.error(
                f"Invalid Paths: {",".join([str(x) for x in not_exist_paths])}"
            )
            return None

        output_dir: Path = Path(args.output_dir).absolute()
        output_dir.mkdir(parents=True, exist_ok=True)

        server_dir: Path = Path(args.server_dir).absolute() if args.server_dir else None

        mode: str = args.mode
        dump_report: bool = args.report
        is_dev: bool = args.dev
        harnesses: list[str] = (
            [x.strip() for x in args.harnesses.split(",")] if args.harnesses else []
        )
        log_level: str = args.log_level
        cg_paths: list[Path] = [Path(x) for x in args.cg.split(",")] if args.cg else []
        workers: int = args.workers

        return CommandLineOption(
            cp_meta=cp_meta,
            jazzer=jazzer,
            joern=joern,
            query=query,
            model_cache=model_cache,
            output_dir=output_dir,
            harnesses=harnesses,
            is_dev=is_dev,
            dump_report=dump_report,
            log_level=log_level,
            cg_paths=cg_paths,
            workers=workers,
            mode=mode,
            server_dir=server_dir,
            shared_dir=shared,
            diff_threashold=args.diff_threashold,
            models=[m.strip() for m in args.models.split(",")] if args.models else None,
            scan_sinks=args.scan_sinks,
        )
