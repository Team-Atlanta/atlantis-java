#!/usr/bin/env python3
import asyncio
import json
import os
import shutil
import traceback
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiofiles
from libCRS import CRS, HarnessRunner, Module, util
from pydantic import BaseModel, Field, field_validator

from .dictgen import InitialDictGenReq, OSSDictGenReq, RefDiffDictGenReq
from .utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    get_env_exports,
    run_process_and_capture_output,
    sanitize_env,
)
from .utils_nfs import (
    get_crs_java_nfs_seedshare_dir,
    get_crs_multilang_nfs_seedshare_dir,
)

CRS_ERR = CRS_ERR_LOG("jazzer-mod")
CRS_WARN = CRS_WARN_LOG("jazzer-mod")


def is_jazzer_module(mod: Module) -> bool:
    return isinstance(mod, Jazzer)


def is_fuzzing_module(mod: Module) -> bool:
    return isinstance(mod, Jazzer) and not isinstance(mod, SeedMerger)


def is_beep_mode_on(mod: Module) -> bool:
    return (
        mod.enabled
        and hasattr(mod.params, "beepseed_search")
        and mod.params.beepseed_search
    )


class JazzerParams(BaseModel):
    enabled: bool = Field(
        ..., description="**Mandatory**, true/false to enable/disable this module."
    )
    mem_size: int = Field(
        4096,
        description="**Optional**, memory size in MB. Default value is 4096, require >= 2048.",
    )
    keep_seed: bool = Field(
        ..., description="**Mandatory**, true/false to keep the seed file."
    )
    len_control: int = Field(
        0, description="**Optional**, libfuzzer -len_control param. Default: 0."
    )
    max_len: Optional[int] = Field(
        1048576,
        description="**Optional**, libfuzzer -max_len param. If unset, will be 1048576 (1M).",
    )
    fuzz_time: int = Field(
        0, description="**Optional**, max fuzzing time. Default: 0 (unlimited)."
    )
    wait_for_llmpocgen: bool = Field(
        False, description="**Optional**, whether to wait for llmpocgen to finish before starting to fuzz. Default: False."
    )

    @field_validator("enabled")
    def enabled_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("enabled must be a boolean")
        return v

    @field_validator("mem_size")
    def mem_size_should_be_big_enough(cls, v):
        if v < 2048:
            raise ValueError("mem_size must be >= 2048")
        return v

    @field_validator("len_control")
    def len_control_should_be_non_negative(cls, v):
        if v < 0:
            raise ValueError("len_control must be >= 0")
        return v

    @field_validator("max_len")
    def max_len_should_be_positive_if_set(cls, v):
        if v is not None and v <= 0:
            raise ValueError("max_len must be > 0 if set")
        return v


class Jazzer(Module, ABC):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: JazzerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, run_per_harness)
        self.envs: Dict[str, str] = {}
        self.ttl_fuzz_time: int = self.crs.ttl_fuzz_time
        self.envs["FUZZ_TTL_FUZZ_TIME"] = str(self.ttl_fuzz_time)
        self.params = params
        self.llm_poc_gen_done_event = asyncio.Event()
        self._init_from_params()

    @abstractmethod
    def _init_from_params(self):
        self.enabled = self.params.enabled
        self.mem_size = self.params.mem_size
        self.len_control = self.params.len_control
        self.max_len = self.params.max_len
        self.envs["FUZZ_KEEP_SEED"] = "on" if self.params.keep_seed else "off"
        # If jazzer is configured with fuzz_time > 0, the actual fuzz_time is the min of
        # the module's fuzz_time and the CRS-wide ttl_fuzz_time
        self.fuzz_time = self.params.fuzz_time
        if self.fuzz_time > 0:
            self.ttl_fuzz_time = min(self.fuzz_time, self.ttl_fuzz_time)
            self.envs["FUZZ_TTL_FUZZ_TIME"] = str(self.ttl_fuzz_time)
        self.wait_for_llmpocgen = self.params.wait_for_llmpocgen

    def _init(self):
        pass

    async def _async_prepare(self):
        return

    async def _async_test(self, hrunner: HarnessRunner):
        util.TODO("Add test")

    async def _async_get_mock_result(self, hrunner: Optional[HarnessRunner]):
        util.TODO("Add mock result")

    async def corpus_file_exists(self, hrunner: HarnessRunner, file_hash: str) -> bool:
        corpus_dirs = [path for path in await self.get_expected_corpus_dirs(hrunner)]
        for corpus_dir in corpus_dirs:
            if (corpus_dir / file_hash).exists():
                return True
        return False

    async def add_corpus_file(self, hrunner: HarnessRunner, seed_file: Path):
        if not self.enabled:
            self.logH(hrunner, f"Module {self.name} is disabled, skip")
            return

        corpus_dirs = [path for path in await self.get_expected_corpus_dirs(hrunner)]
        if len(corpus_dirs) == 0:
            self.logH(hrunner, "No corpus directories found to add seed file.")
            return

        if self.crs.verbose:
            self.logH(hrunner, "Adding seed file to the following corpus directories:")
            for corpus_dir in corpus_dirs:
                self.logH(hrunner, f" - {corpus_dir.resolve()}")

        # 6-byte random hash suffix to avoid name conflicts
        seed_file_name = f"add-{seed_file.name}-{uuid.uuid4().hex[:6]}"

        for corpus_dir in corpus_dirs:
            corpus_dir.mkdir(parents=True, exist_ok=True)
            dst_file = corpus_dir / seed_file_name
            shutil.copyfile(seed_file, dst_file)
            if self.crs.verbose:
                self.logH(
                    hrunner,
                    f"Added seed file {seed_file.resolve()} into corpus_dir {corpus_dir.resolve()} as {dst_file.resolve()}",
                )

    async def notify_llm_poc_gen_done(self):
        if self.enabled and self.wait_for_llmpocgen:
            self.llm_poc_gen_done_event.set()

    async def get_expected_fuzz_instance_dirs(
        self, hrunner: HarnessRunner
    ) -> List[Path]:
        cpu_list = await self.crs.cpuallocator.poll_allocation(hrunner, self.name)
        return [
            hrunner.workdir / f"fuzz/{self.name}-r{idx}" for idx in range(len(cpu_list))
        ]

    async def get_expected_x(self, hrunner: HarnessRunner, x: str) -> List[Path]:
        return [
            dir_path / x
            for dir_path in await self.get_expected_fuzz_instance_dirs(hrunner)
        ]

    async def get_expected_result_jsons(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "result.json")

    async def get_expected_corpus_dirs(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "corpus_dir")

    async def get_expected_fuzz_dict(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "fuzz.dict")
    
    async def get_expected_exec_files(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "jacoco.exec")

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        raise Exception("Not implemented")

    @staticmethod
    def get_artifact_abspath(result_json_path: Path, artifact_name: str) -> str:
        """Get the absolute path to an artifact file."""
        return str((result_json_path.parent / "artifacts" / artifact_name).resolve())

    async def _init_result_json(self, result_json: Path, data: dict):
        async with aiofiles.open(result_json, "w") as f:
            await f.write(json.dumps(data, sort_keys=True, indent=2))

    def _prepare_fuzz_directories(
        self, hrunner: HarnessRunner, fuzz_id: str, workdir: Path
    ) -> Tuple[Path, Path]:
        fuzz_dir = workdir / "fuzz" / fuzz_id
        fuzz_dir.mkdir(parents=True, exist_ok=True)

        tmp_dir = Path(f"/tmp-{hrunner.harness.name}-{fuzz_id}-{uuid.uuid4().hex}")

        return fuzz_dir, tmp_dir

    def _update_option_envs(self, hrunner: HarnessRunner) -> dict:
        """Update env variables based on harness options."""
        harness = hrunner.harness
        envs = {}
        # mem size
        mem_size = self.mem_size
        opt_mem_size = self.crs.meta.get_harness_rss_limit_mb(harness)
        if opt_mem_size is not None:
            self.logH(
                hrunner,
                f"rss_limit_mb: min of {mem_size} (cfg) and {opt_mem_size} (opt)",
            )
            mem_size = min(mem_size, opt_mem_size)
        else:
            self.logH(hrunner, f"rss_limit_mb: init as {mem_size} (cfg)")
        envs["FUZZ_JAZZER_MEM"] = str(mem_size)
        # len control
        len_control = self.len_control
        opt_len_control = self.crs.meta.get_harness_len_control(harness)
        if opt_len_control is not None:
            self.logH(
                hrunner,
                f"len_control: min of {len_control} (cfg) and {opt_len_control} (opt)",
            )
            len_control = min(len_control, opt_len_control)
        else:
            self.logH(hrunner, f"len_control: init as {len_control} (cfg)")
        if len_control != 0:
            envs["FUZZ_LEN_CONTROL"] = str(len_control)
        # max len
        max_len = self.crs.meta.get_harness_max_len(harness)
        if max_len is None:
            max_len = self.max_len
            self.logH(hrunner, f"max_len: init as {max_len} (cfg)")
        else:
            self.logH(hrunner, f"max_len: inherited from opt ({max_len})")
        if max_len is not None:
            envs["FUZZ_MAX_LEN"] = str(max_len)
        timeout_exitcode = self.crs.meta.get_harness_timeout_exitcode(harness)
        if timeout_exitcode is not None:
            self.logH(
                hrunner, f"timeout_exitcode: inherited from opt ({timeout_exitcode})"
            )
            envs["FUZZ_TIMEOUT_EXITCODE"] = str(timeout_exitcode)
        return envs

    @abstractmethod
    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        """Sub-class use this method to control more envs right before fuzzing."""
        return env

    async def _prepare_environment(
        self,
        hrunner: HarnessRunner,
        fuzz_id: str,
        cpu_list: List[int],
        repeat_idx: int,
        cp_name: str,
        target_harness: str,
        target_class: str,
        tmp_dir: Path,
        fuzz_dir: Path,
    ) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(self.envs)
        env["FUZZ_ID"] = fuzz_id
        env["FUZZ_BOUND_CPULIST"] = ",".join([str(c) for c in cpu_list])
        env["FUZZ_REPEAT_IDX"] = str(repeat_idx)
        env["FUZZ_TARGET_CP"] = cp_name
        env["FUZZ_TARGET_HARNESS"] = target_harness
        env["FUZZ_TARGET_CLASS"] = target_class
        env["FUZZ_CWD"] = str(tmp_dir.resolve())

        customized_JAVA_HOME = self.crs.meta.get_harness_JAVA_HOME(hrunner.harness)
        if customized_JAVA_HOME:
            env["JAVA_HOME"] = customized_JAVA_HOME
        customized_LD_LIBRARY_PATH = self.crs.meta.get_harness_LD_LIBRARY_PATH(
            hrunner.harness
        )
        if customized_LD_LIBRARY_PATH:
            env["LD_LIBRARY_PATH"] = (
                env.get("LD_LIBRARY_PATH", "") + ":" + customized_LD_LIBRARY_PATH
            )
        customized_JVM_LD_LIBRARY_PATH = self.crs.meta.get_harness_JVM_LD_LIBRARY_PATH(
            hrunner.harness
        )
        if customized_JVM_LD_LIBRARY_PATH:
            env["JVM_LD_LIBRARY_PATH"] = (
                env.get("JVM_LD_LIBRARY_PATH", "")
                + ":"
                + customized_JVM_LD_LIBRARY_PATH
            )
        customized_ASAN_OPTIONS = self.crs.meta.get_harness_ASAN_OPTIONS(
            hrunner.harness
        )
        if customized_ASAN_OPTIONS:
            env["ASAN_OPTIONS"] = customized_ASAN_OPTIONS
        if self.crs.deepgen.enabled:
            if hasattr(self, "deepgen_consumer") and self.deepgen_consumer:
                env["ATLJAZZER_ZMQ_ROUTER_ADDR"] = self.crs.deepgen.zmq_url
                env["ATLJAZZER_ZMQ_HARNESS_ID"] = hrunner.harness.name
                env["ATLJAZZER_ZMQ_DEALER_ID"] = env["FUZZ_ID"]
                env["ATLJAZZER_ZMQ_DEALER_LOG"] = str(
                    (fuzz_dir / "dealer.log").resolve()
                )

        initial_corpus = self.crs.meta.get_harness_initial_corpus_path(hrunner.harness)
        env["FUZZ_INITIAL_CORPUS"] = str(initial_corpus.resolve())

        env.update(self._update_option_envs(hrunner))
        return await self._fuzzer_specific_env_setup(hrunner, env)

    async def _write_command_script(
        self,
        command_sh: Path,
        cpu_list: List[int],
        fuzz_dir: Path,
        cp_name: str,
        env: Dict[str, str],
    ) -> str:
        command = f"""#!/bin/bash
# Env
{get_env_exports(env)}
# Cmd
mkdir -p $FUZZ_CWD && cd $FUZZ_CWD
taskset -c {",".join([str(c) for c in cpu_list])} \\
  stdbuf -e 0 -o 0 \\
    bash $JAVA_CRS_SRC/javacrs_modules/scripts/run-jazzer.sh \\
      {self.jazzer_dir.resolve()} \\
      {fuzz_dir.resolve()}
"""
        async with aiofiles.open(command_sh, "w") as f:
            await f.write(command)
        command_sh.chmod(0o755)
        return command

    async def _prepare_initial_dict(
        self, fuzz_id: str, hrunner: HarnessRunner, fuzz_dir: Path
    ):
        self.logH(hrunner, f"Requesting dict generation for {fuzz_id}")
        fuzz_dict_path = fuzz_dir / "fuzz.dict"
        await self.crs.dictgen.request_dict_gen(
            harness_name=hrunner.harness.name,
            target_dict_path=fuzz_dict_path,
            dict_gen_reqs=[
                InitialDictGenReq(),
                RefDiffDictGenReq(),
                OSSDictGenReq(),
            ],
        )

    async def _async_run_instance(
        self, hrunner: HarnessRunner, cpu_list: list, repeat_idx: int
    ) -> int:
        try:
            fuzz_id = f"{self.name}-r{repeat_idx}"
            workdir = hrunner.workdir
            cp_name = hrunner.crs.cp.name
            target_harness = hrunner.harness.name
            target_class = hrunner.crs.meta.get_harness_class(hrunner.harness)
            target_classpath = ":".join(
                hrunner.crs.meta.get_harness_classpath(hrunner.harness)
            )

            fuzz_dir, tmp_dir = self._prepare_fuzz_directories(
                hrunner, fuzz_id, workdir
            )

            # Wait for llmpocgen to finish before starting to fuzz (if configured)
            if self.wait_for_llmpocgen:
                self.logH(
                    hrunner,
                    f"{fuzz_id} is waiting for llmpocgen to finish before starting to fuzz",
                )
                await self.llm_poc_gen_done_event.wait()

            env = await self._prepare_environment(
                hrunner,
                fuzz_id,
                cpu_list,
                repeat_idx,
                cp_name,
                target_harness,
                target_class,
                tmp_dir,
                fuzz_dir,
            )

            result_json = fuzz_dir / "result.json"
            command_sh = fuzz_dir / "command.sh"

            await self._write_command_script(
                command_sh,
                cpu_list,
                fuzz_dir,
                cp_name,
                env,
            )

            init_data = {
                "cp": cp_name,
                "harness": target_class,
                "harness_id": target_harness,
                "target_classpath": target_classpath,
                "module": self.name,
                "repeat_idx": repeat_idx,
                "fuzz_id": fuzz_id,
                "env": sanitize_env(env),
                "fuzz_data": {
                    "cov_over_time": [],
                    "ft_over_time": [],
                    "rss_over_time": [],
                    "log_crash_over_time": [],
                    "artifact_over_time": [],
                    "log_dedup_crash_over_time": [],
                    "ttl_round": 0,
                    "last_cov": 0,
                    "last_ft": 0,
                    "last_rss": 0,
                    "max_cov": 0,
                    "max_ft": 0,
                    "max_rss": 0,
                },
            }
            await self._init_result_json(result_json, init_data)
            await self._prepare_initial_dict(fuzz_id, hrunner, fuzz_dir)

            self.logH(
                hrunner, f"Running {fuzz_id} with command in {command_sh.resolve()}"
            )
            output_log = fuzz_dir / "run.log"
            ret = await run_process_and_capture_output(command_sh, output_log)
            if ret == 0:
                # NOTE: jazzer script will internally kill its fuzzing process and return 0
                self.logH(hrunner, f"{fuzz_id} is forced killed with ret {ret})")
            else:
                self.logH(
                    hrunner,
                    f"{fuzz_id} of {self.name}/{self.jazzer_dir.name} unexpectedly exits with ret {ret})",
                )
            return ret
        except Exception as e:
            self.logH(
                hrunner,
                f"{CRS_ERR} Exception in instance {repeat_idx}: {e} {traceback.format_exc()}",
            )
            raise

    async def _async_run_impl(self, hrunner: HarnessRunner) -> List[Any]:
        cpu_list = await self.crs.cpuallocator.poll_allocation(hrunner, self.name)
        tasks = []

        for repeat_idx, cpu_no in enumerate(cpu_list):
            # Each Jazzer instance uses one CPU core
            task = asyncio.create_task(
                self._async_run_instance(hrunner, [cpu_no], repeat_idx)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _async_run(self, hrunner: HarnessRunner):
        """
        Run the Jazzer fuzzer on the given HarnessRunner:
          - 1. Pre-fuzzing setup (directories, env vars, etc.)
          - 2. Run the fuzzer asynchronously
          - 3. Fuzzing post-processing (run in step 2)
        """
        if not self.enabled:
            self.logH(hrunner, f"Module {self.name} is disabled, skip")
            return

        self.logH(hrunner, f"Module {self.name} starts")
        try:
            results = await self._async_run_impl(hrunner)
            for idx, result in enumerate(results):
                if isinstance(result, Exception):
                    exception_trace = "".join(
                        traceback.format_exception(
                            type(result), result, result.__traceback__
                        )
                    )
                    self.logH(
                        hrunner,
                        f"{CRS_ERR} Instance {idx} encountered exception:\n{exception_trace}",
                    )
                else:
                    self.logH(
                        hrunner, f"Instance {idx} completes with ret code: {result}"
                    )
            self.logH(hrunner, f"Module {self.name} completes")
        except Exception as e:
            exception_trace = "".join(
                traceback.format_exception(type(e), e, e.__traceback__)
            )
            self.logH(
                hrunner,
                f"{CRS_ERR} Module {self.name} meets exception:\n{exception_trace}",
            )


class AIxCCJazzerParams(JazzerParams):
    pass  # No additional parameters needed


class AIxCCJazzer(Jazzer):
    """AIxCC AFC Official Jazzer"""

    def __init__(
        self,
        name: str,
        crs: CRS,
        params: AIxCCJazzerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, params, run_per_harness)

    def _init_from_params(self):
        super()._init_from_params()
        self.jazzer_dir = Path("/classpath/aixcc-jazzer")

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        return []

    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        return env


class AtlJazzerParams(JazzerParams):
    beepseed_search: bool = Field(
        False,
        description="**Optional**, true/false to enable/disable beepseed search.",
    )
    deepgen_consumer: bool = Field(
        ...,
        description="**Mandatory**, true/false to enable/disable consuming seeds from deepgen module.",
    )
    jacoco_cov_dump_period: Optional[int] = Field(
        None,
        description="**Optional**, JaCoCo coverage dump period in seconds (positive integer). Default value is None.",
    )

    @field_validator("beepseed_search", "deepgen_consumer")
    def boolean_validator(cls, v, field):
        if not isinstance(v, bool):
            raise ValueError(f"{field.name} must be a boolean")
        return v

    @field_validator("jacoco_cov_dump_period")
    def jacoco_period_should_be_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError("jacoco_cov_dump_period must be a positive integer or None")
        return v


class AtlJazzer(Jazzer):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: AtlJazzerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, params, run_per_harness)

    def _init_from_params(self):
        super()._init_from_params()
        self.jazzer_dir = Path("/classpath/atl-jazzer")
        # BEEPSEED SEARCH
        self.envs["FUZZ_BEEPSEED_SEARCH"] = (
            "on" if self.params.beepseed_search else "off"
        )
        # DEEPGEN CONSUMER
        self.deepgen_consumer = self.params.deepgen_consumer
        # DIRECTED FUZZ CFG OFF
        self.directed: bool = False
        self.envs["FUZZ_DIRECTED_TGT_PATH"] = ""
        self.exploration_time: Optional[int] = None
        self.envs["FUZZ_DIRECTED_EXPLORE_TIME"] = ""
        self.directed_time: Optional[int] = None
        self.envs["FUZZ_DIRECTED_TIME"] = ""

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "beeps")

    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        if self.crs.sinkmanager.enabled:
            sink_conf_file = self.crs.meta.get_custom_sink_conf_path()
            env["FUZZ_CUSTOM_SINK_CONF"] = str(sink_conf_file.resolve())
        # Disable Jazzer's built-in hardcoded sinkpoint table when ssmode is on,
        # so only sinks fed via FUZZ_CUSTOM_SINK_CONF get instrumented.
        env["FUZZ_SSMODE"] = "on" if self.crs.is_ssmode() else "off"
        # Set JACOCO_COV_DUMP_PERIOD environment variable if specified
        if self.params.jacoco_cov_dump_period is not None:
            env["JACOCO_COV_DUMP_PERIOD"] = str(self.params.jacoco_cov_dump_period)
        return env


class AtlDirectedJazzerParams(AtlJazzerParams):
    exploration_time: Optional[int] = Field(
        None,
        description="**Optional**, directed fuzzing exploration phase time in seconds (positive integer). Default value is None.",
    )
    directed_time: Optional[int] = Field(
        None,
        description="**Optional**, directed fuzzing directed phase time in seconds (positive integer). Default value is None.",
    )

    @field_validator("exploration_time", "directed_time")
    def times_should_be_positive(cls, v, field):
        if v is not None and v <= 0:
            raise ValueError(f"{field.name} must be a positive integer or None")
        return v


class AtlDirectedJazzer(AtlJazzer):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: AtlJazzerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, params, run_per_harness)

    def _init_from_params(self):
        super()._init_from_params()
        self.jazzer_dir = Path("/classpath/atl-jazzer")
        # BEEPSEED SEARCH
        self.envs["FUZZ_BEEPSEED_SEARCH"] = (
            "on" if self.params.beepseed_search else "off"
        )
        # DIRECTED FUZZ
        self.directed: bool = True
        self.exploration_time: Optional[int] = self.params.exploration_time
        self.envs["FUZZ_DIRECTED_EXPLORE_TIME"] = (
            str(self.exploration_time) if self.exploration_time is not None else ""
        )
        self.directed_time: Optional[int] = self.params.directed_time
        self.envs["FUZZ_DIRECTED_TIME"] = (
            str(self.directed_time) if self.directed_time is not None else ""
        )

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "beeps")

    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        if self.crs.sinkmanager.enabled:
            sink_conf_file = self.crs.meta.get_custom_sink_conf_path()
            env["FUZZ_CUSTOM_SINK_CONF"] = str(sink_conf_file.resolve())
        # NOTE: must done at runtime as self.crs.staticanalysis is unavailable in constructor
        self.directed_tgt_path = self.crs.staticanalysis.get_directed_tgt_path()
        if self.directed_tgt_path:
            env["FUZZ_DIRECTED_TGT_PATH"] = str(self.directed_tgt_path.resolve())
        else:
            env["FUZZ_DIRECTED_TGT_PATH"] = ""
        # Set FUZZ_SSMODE environment variable
        env["FUZZ_SSMODE"] = "on" if self.crs.is_ssmode() else "off"

        return env


class AtlLibAFLJazzerParams(JazzerParams):
    beepseed_search: bool = Field(
        False,
        description="**Optional**, true/false to enable/disable beepseed search.",
    )

    @field_validator("beepseed_search")
    def beepseed_search_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("beepseed_search must be a boolean")
        return v


class AtlLibAFLJazzer(Jazzer):
    def __init__(
        self,
        name: str,
        crs: CRS,
        params: AtlLibAFLJazzerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, params, run_per_harness)

    def _init_from_params(self):
        super()._init_from_params()
        self.jazzer_dir = Path("/classpath/atl-libafl-jazzer")
        self.envs["FUZZ_BEEPSEED_SEARCH"] = (
            "on" if self.params.beepseed_search else "off"
        )

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "beeps")

    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        if self.crs.sinkmanager.enabled:
            sink_conf_file = self.crs.meta.get_custom_sink_conf_path()
            env["FUZZ_CUSTOM_SINK_CONF"] = str(sink_conf_file.resolve())
        # Set FUZZ_SSMODE environment variable
        env["FUZZ_SSMODE"] = "on" if self.crs.is_ssmode() else "off"
        return env


class SeedMergerParams(JazzerParams):
    beepseed_search: bool = True  # Always true for seed merger
    deepgen_consumer: bool = False  # Always false for seed merger

    set_cover_merge: bool = Field(
        False,
        description="**Optional**, true/false to enable/disable set_cover_merge.",
    )

    @field_validator("set_cover_merge")
    def set_cover_merge_should_be_boolean(cls, v):
        if not isinstance(v, bool):
            raise ValueError("set_cover_merge must be a boolean")
        return v


class SeedMerger(AtlJazzer):
    """Jazzer for merging seed files"""

    def __init__(
        self,
        name: str,
        crs: CRS,
        params: SeedMergerParams,
        run_per_harness: bool,
    ):
        super().__init__(name, crs, params, run_per_harness)

    def _init_from_params(self):
        super()._init_from_params()
        self.jazzer_dir = Path("/classpath/atl-jazzer")
        self.envs["FUZZ_MERGE_SEED"] = "on"
        self.envs["FUZZ_BEEPSEED_SEARCH"] = "on"
        # DEEPGEN CONSUMER
        self.deepgen_consumer = self.params.deepgen_consumer
        self.set_cover_merge = self.params.set_cover_merge

    async def get_expected_beepseed_dir(self, hrunner: HarnessRunner) -> List[Path]:
        return await self.get_expected_x(hrunner, "beeps")

    def get_expected_merge_from_dir(self, hrunner) -> Path:
        return hrunner.workdir / "fuzz" / f"{self.name}-r0" / "merge-from-corpus"

    def try_get_expected_merge_from_dir(self, harness_name: str) -> Path | None:
        for hrunner in self.crs.hrunners:
            if hrunner.harness.name == harness_name:
                return self.get_expected_merge_from_dir(hrunner)
        return None

    def get_expected_full_cov_dir(self, hrunner) -> Path:
        # I.e., merge to dir, cov & value profile
        dir = hrunner.workdir / "fuzz" / f"{self.name}-r0" / "corpus_dir"
        dir.mkdir(parents=True, exist_ok=True)
        return dir

    def get_expected_full_cov_only_dir(self, hrunner) -> Path:
        # I.e., merge to dir, but cov-only
        dir = hrunner.workdir / "fuzz" / f"{self.name}-r0" / "corpus_dir-covonly"
        dir.mkdir(parents=True, exist_ok=True)
        return dir

    async def _fuzzer_specific_env_setup(
        self, hrunner, env: Dict[str, str]
    ) -> Dict[str, str]:
        if self.crs.sinkmanager.enabled:
            sink_conf_file = self.crs.meta.get_custom_sink_conf_path()
            env["FUZZ_CUSTOM_SINK_CONF"] = str(sink_conf_file.resolve())
        # Receive raw corpus files from seedsharer
        env["FUZZ_MERGE_FROM_RAW_DIR"] = str(
            self.get_expected_merge_from_dir(hrunner).resolve()
        )
        # Used for merging seed files
        env["FUZZ_MERGE_FROM_TEMP_DIR"] = env["FUZZ_MERGE_FROM_RAW_DIR"] + "-temp"
        harness_id = hrunner.harness.name
        crs_java_nfs_dir = get_crs_java_nfs_seedshare_dir(harness_id)
        if crs_java_nfs_dir:
            env["FUZZ_CRS_JAVA_NFS_SEED_DIR"] = str(crs_java_nfs_dir.resolve())
        crs_multilang_nfs_dir = get_crs_multilang_nfs_seedshare_dir(harness_id)
        if crs_multilang_nfs_dir:
            env["FUZZ_CRS_MULTILANG_NFS_SEED_DIR"] = str(
                crs_multilang_nfs_dir.resolve()
            )
            local_dir = self.crs.seedsharer.get_multilang_seed_local_dir(harness_id)
            env["FUZZ_CRS_MULTILANG_LOCAL_SEED_DIR"] = str(local_dir.resolve())
        if self.set_cover_merge:
            env["FUZZ_SET_COVER_MERGE"] = "on"
        return env

    async def get_expected_fuzz_instance_dirs(
        self, hrunner: HarnessRunner
    ) -> List[Path]:
        cpu_list = await self.crs.cpuallocator.poll_allocation(hrunner, self.name)
        return [hrunner.workdir / f"fuzz/{self.name}-r0"] if cpu_list else []

    async def _async_run_impl(self, hrunner: HarnessRunner) -> List[Any]:
        cpu_list = await self.crs.cpuallocator.poll_allocation(hrunner, self.name)
        tasks = []

        if len(cpu_list) > 0:
            self.logH(hrunner, f"Use CPU {cpu_list} for seed merging")
            task = asyncio.create_task(self._async_run_instance(hrunner, cpu_list, 0))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
