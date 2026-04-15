#!/usr/bin/env python3

import json
import logging
import os
import subprocess
import traceback
from pathlib import Path

from ..utils import CRS_ERR_LOG, CRS_WARN_LOG, get_env_exports, sanitize_env

CRS_ERR = CRS_ERR_LOG("jazzer")
CRS_WARN = CRS_WARN_LOG("jazzer")
logger = logging.getLogger(__name__)


class JazzerFuzzer:
    def __init__(
        self,
        jazzer_dir: Path,
        work_dir: Path,
        cp_name: str,
        target_harness: str,
        fuzz_target: str,
        target_classpath: str,
        custom_sink_conf_path: Path | None,
        cpu_id: int,
        custom_args: list = None,
    ):
        self.jazzer_dir = Path(jazzer_dir)
        jazzer_executable = self.jazzer_dir / "jazzer"
        if not jazzer_executable.exists():
            raise ValueError(
                f"{CRS_ERR} Jazzer executable not found at {jazzer_executable}"
            )

        self.work_dir = Path(work_dir)
        self.cp_name = cp_name
        self.target_harness = target_harness
        self.fuzz_target = fuzz_target
        self.target_classpath = target_classpath
        self.custom_sink_conf_path = custom_sink_conf_path
        self.cpu_id = cpu_id
        self.custom_args = custom_args if custom_args is not None else []

        self.corpus_dir = self.work_dir / "corpus_dir"
        self.dict_file = self.work_dir / "fuzz.dict"
        self.result_json = self.work_dir / "result.json"
        self.fuzz_log = self.work_dir / "fuzz.log"

        self.dict_values = set()

    def add_dict_entries(self, values: str | list[str] | set[str]):
        if isinstance(values, str):
            self.dict_values.add(values)
        else:
            for value in values:
                self.dict_values.add(value)

        return len(self.dict_values)

    def add_custom_args(self, args: str | list[str]):
        if isinstance(args, str):
            self.custom_args.append(args)
        else:
            self.custom_args.extend(args)

        return self.custom_args

    def add_corpus_file(self, content: bytes, filename: str):
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        target_file = self.corpus_dir / filename
        with open(target_file, "wb") as f:
            f.write(content)

        return target_file

    def _write_dict_file(self):
        self.dict_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.dict_file, "w") as f:
            f.write("# Dictionary for Jazzer fuzzing\n")

            for i, value in enumerate(self.dict_values, 1):
                # Escape non-printable characters and backslash
                escaped_value = ""
                for char in value:
                    if char == "\\":
                        escaped_value += "\\\\"
                    elif ord(char) < 32 or ord(char) > 126:
                        escaped_value += f"\\x{ord(char):02x}"
                    else:
                        escaped_value += char

                f.write(f'k_{i}="{escaped_value}"\n')

    def _write_command_script(self, cwd: str):
        command_sh = self.work_dir / "expkit-command.sh"
        cmd_content = f"""#!/bin/bash
# Environment variables
{get_env_exports(self.env)}

# Create and use a dedicated working directory
mkdir -p {cwd}
cd {cwd}

# Run jazzer
taskset -c {self.cpu_id} \\
  stdbuf -e 0 -o 0 \\
    bash {Path(__file__).parent / "scripts" / "run-jazzer.sh"} \\
      {self.jazzer_dir} \\
      {self.work_dir}
"""
        with open(command_sh, "w") as f:
            f.write(cmd_content)

        command_sh.chmod(0o755)
        return command_sh

    def _init_result_json(self, fuzz_id: str, fuzz_time: int, mem_size: int, verify_only: bool = False):
        if not self.result_json.parent.exists():
            self.result_json.parent.mkdir(parents=True, exist_ok=True)

        self.env = os.environ.copy()
        self.env["FUZZ_TTL_FUZZ_TIME"] = str(fuzz_time)
        self.env["FUZZ_JAZZER_MEM"] = str(mem_size)
        self.env["FUZZ_BOUND_CPULIST"] = str(self.cpu_id)
        self.env["FUZZ_CUSTOM_ARGS"] = " ".join(self.custom_args)
        self.env["FUZZ_TARGET_HARNESS"] = self.target_harness
        if self.custom_sink_conf_path is not None:
            self.env["FUZZ_CUSTOM_SINK_CONF"] = self.custom_sink_conf_path
        if verify_only:
            self.env["FUZZ_VERIFY_ONLY"] = "1"

        init_data = {
            "cp": self.cp_name,
            "harness": self.fuzz_target,
            "harness_id": self.target_harness,
            "fuzz_id": fuzz_id,
            "target_classpath": self.target_classpath,
            "fuzz_time": fuzz_time,
            "mem_size": mem_size,
            "env": sanitize_env(self.env),
            "fuzz_data": {
                "cov_over_time": [],
                "ft_over_time": [],
                "rss_over_time": [],
                "log_crash_over_time": [],
                "artifact_over_time": [],
                "ttl_round": 0,
                "last_cov": 0,
                "last_ft": 0,
                "last_rss": 0,
                "max_cov": 0,
                "max_ft": 0,
                "max_rss": 0,
            },
        }

        with open(self.result_json, "w") as f:
            json.dump(init_data, f, indent=2)

    def fuzz(self, fuzz_id: str, fuzz_time: int, mem_size: int = 4096, verify_only: bool = False):
        try:
            self._write_dict_file()
            logger.info(f"Fuzz dict file has {len(self.dict_values)} entries")

            self._init_result_json(fuzz_id, fuzz_time, mem_size, verify_only=verify_only)

            cwd = f"/tmp-{fuzz_id}"
            command_sh = self._write_command_script(cwd)
            logger.info(
                f"Starting fuzzing of {fuzz_id} for {self.fuzz_target} on CPU {self.cpu_id} in cwd: {cwd}"
            )

            process = subprocess.Popen(
                ["bash", str(command_sh)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in iter(process.stdout.readline, ""):
                logger.debug(line.strip())

            process.stdout.close()
            returncode = process.wait()

            if returncode != 0:
                logger.error(
                    f"{CRS_ERR} Jazzer process failed with return code {returncode}"
                )
                raise subprocess.CalledProcessError(
                    returncode, ["bash", str(command_sh)]
                )

            if not self.result_json.exists():
                logger.error(f"{CRS_ERR} Result JSON not found at {self.result_json}")
                raise RuntimeError("Fuzzing completed but no result file was generated")

            logger.info("Fuzzing process completed")
            return self.result_json

        except Exception as e:
            err_str = f"{CRS_ERR} Fuzzing failed: {str(e)}"
            logger.error(f"{err_str} with traceback:\n{traceback.format_exc()}")
            raise RuntimeError(err_str)

    def clone(self, work_dir: Path):
        return JazzerFuzzer(
            jazzer_dir=self.jazzer_dir,
            work_dir=work_dir,
            cp_name=self.cp_name,
            target_harness=self.target_harness,
            fuzz_target=self.fuzz_target,
            target_classpath=self.target_classpath,
            custom_sink_conf_path=self.custom_sink_conf_path,
            cpu_id=self.cpu_id,
            custom_args=list(self.custom_args),
        )
