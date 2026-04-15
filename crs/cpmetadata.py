"""
This module is a place which contains all heuristics for inferring metadata for a given CP. Every module inside CRS is expected to directly use its inferred result.

Metadata example for CP aixcc/jvm/mock-java, it is saved in self.meta_path (CP_METADATA_FILE). Optional means the field may not exist if it is not found.

{
  "built_path": "/out",
  "cp_full_src": "/src",
  "cp_name": "aixcc/jvm/mock-java",
  "sinkpoint_path": "/crs-workdir/worker-0/metadata/aixcc/jvm/mock-java/sinkpoints.json",
  "harnesses": {
    "OssFuzz1": {
      "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
      "JVM_LD_LIBRARY_PATH": "/usr/lib/jvm/java-17-openjdk-amd64/lib/server",
      "LD_LIBRARY_PATH": "/usr/lib/jvm/java-17-openjdk-amd64/lib/server:/out",
      "bin_path": "/out/OssFuzz1",
      "classpath": [
        "/out/mock_java.jar",
        "/out/gson-2.8.6.jar",
        "/out/.",
        "/out"
      ],
      "name": "OssFuzz1",
      "src_path": "oss-fuzz/projects/aixcc/jvm/mock-java/fuzz/OssFuzz1.java",
      "target_class": "OssFuzz1",
      "target_method": "fuzzerTestOneInput"
    }
  },
  "pkg2files": {
    "": [
      "/src/oss-fuzz/projects/aixcc/jvm/mock-java/fuzz/OssFuzz1.java"
    ],
    "com.aixcc.mock_java": [
      "/src/repo/src/main/java/com/aixcc/mock_java/App.java",
      "/src/repo/src/test/java/com/aixcc/mock_java/AppTest.java"
    ]
  },
  "proj_path": "/src/oss-fuzz/projects/aixcc/jvm/mock-java",
  "ref_diff_path": "/src/oss-fuzz/projects/aixcc/jvm/mock-java/ref.diff",
  "repo_src_path": "/src/repo"
}
"""

import configparser
import glob
import hashlib
import json
import os
import subprocess
import traceback
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

import javalang
import yaml
from javacrs_modules.utils import (
    CRS_ERR_LOG,
    CRS_WARN_LOG,
    atomic_write_file_sync,
    flatten_dir_copy_sync,
    unzip_sync,
)
from javacrs_modules.utils_nfs import (
    get_crs_java_nfs_seedshare_dir,
    get_crs_java_share_cpmeta_path,
    get_crs_multilang_nfs_seedshare_dir,
)
from libCRS import CP, CRS, CP_Harness

CRS_ERR = CRS_ERR_LOG("cpmeta")
CRS_WARN = CRS_WARN_LOG("cpmeta")

IN_COMPETITION = os.environ.get("JAVA_CRS_IN_COMPETITION", "")


class ArgExtractor(ABC):
    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def extract(self, log_f, cmdline_args, env_vars):
        pass

    @abstractmethod
    def to_json(self, log_f):
        pass

    @staticmethod
    def extract_all(log_f, jazzer_args_json: Path):
        try:
            with open(jazzer_args_json) as f:
                jazzer_data = json.load(f)

            cmd_args = jazzer_data.get("cmd_args", [])
            env_vars = jazzer_data.get("env_vars", {})

            # TODO: any other necessary jvm args/env vars/jazzer args?
            extractors = [
                classpathCmdArg(),
                target_classCmdArg(),
                target_argsCmdArg(),
                JAVA_HOMEEnvVar(),
                LD_LIBRARY_PATHEnvVar(),
                JVM_LD_LIBRARY_PATHEnvVar(),
                ASAN_OPTIONSEnvVar(),
            ]

            results = {}
            for extractor in extractors:
                try:
                    extractor.extract(log_f, cmd_args, env_vars)
                    results.update(extractor.to_json())
                except Exception as e:
                    log_f(
                        f"{CRS_ERR} extracting {extractor.name}: {e}, {traceback.format_exc()}"
                    )

            return results

        except Exception as e:
            log_f(f"{CRS_ERR} parsing jazzer_args json: {e}, {traceback.format_exc()}")
            return {}


class classpathCmdArg(ArgExtractor):
    """classpath (--cp)"""

    @property
    def name(self):
        return "classpath"

    def extract(self, log_f, cmdline_args, env_vars):
        last_cp_value = ""
        for arg in cmdline_args:
            if arg.startswith("--cp="):
                last_cp_value = arg[5:].strip()
        classpath = last_cp_value.split(":") if last_cp_value else []
        self.classpath = []
        for entry in classpath:
            if not entry:
                continue
            if not os.path.isabs(entry):
                self.classpath.append(os.path.join(env_vars["PWD"], entry))
            else:
                self.classpath.append(entry)
        log_f(f"Extracted classpath: {self.classpath}")

    def to_json(self):
        return {"classpath": self.classpath}


class target_classCmdArg(ArgExtractor):
    """--target_class"""

    @property
    def name(self):
        return "target_class"

    def extract(self, log_f, cmdline_args, env_vars):
        self.target_class = None
        for arg in cmdline_args:
            if arg.startswith("--target_class="):
                self.target_class = arg[15:].strip()
        if not self.target_class:
            # NOTE: we can't do any fuzz without target_class
            log_f(
                f"{CRS_ERR} target_class not found in jazzer args of the given harness"
            )
            exit(1)
        else:
            log_f(f"Extracted target_class: {self.target_class}")

    def to_json(self):
        return {"target_class": self.target_class}


class target_argsCmdArg(ArgExtractor):
    """--target_args"""

    @property
    def name(self):
        return "target_args"

    def extract(self, log_f, cmdline_args, env_vars):
        for arg in cmdline_args:
            if arg.startswith("--target_args="):
                self.target_args = arg[14:].strip()
                return
        self.target_args = None
        log_f(f"Extracted target_args: {self.target_args}")

    def to_json(self):
        return {"target_args": self.target_args} if self.target_args else {}


class JAVA_HOMEEnvVar(ArgExtractor):
    """JAVA_HOME"""

    @property
    def name(self):
        return "JAVA_HOME"

    def extract(self, log_f, cmdline_args, env_vars):
        JAVA_HOME = env_vars.get("JAVA_HOME", None)
        if not os.path.isabs(JAVA_HOME):
            JAVA_HOME = os.path.join(env_vars["PWD"], JAVA_HOME)
        self.JAVA_HOME = JAVA_HOME
        log_f(f"Extracted JAVA_HOME: {self.JAVA_HOME}")

    def to_json(self):
        return {"JAVA_HOME": self.JAVA_HOME} if self.JAVA_HOME else {}


class LD_LIBRARY_PATHEnvVar(ArgExtractor):
    """LD_LIBRARY_PATH"""

    @property
    def name(self):
        return "LD_LIBRARY_PATH"

    def extract(self, log_f, cmdline_args, env_vars):
        LD_LIBRARY_PATH = env_vars.get("LD_LIBRARY_PATH", None)
        paths = LD_LIBRARY_PATH.split(":") if LD_LIBRARY_PATH else []
        self.LD_LIBRARY_PATH = []
        for path in paths:
            if not path:
                continue
            if not os.path.isabs(path):
                self.LD_LIBRARY_PATH.append(os.path.join(env_vars["PWD"], path))
            else:
                self.LD_LIBRARY_PATH.append(path)
        self.LD_LIBRARY_PATH = ":".join(self.LD_LIBRARY_PATH)
        log_f(f"Extracted LD_LIBRARY_PATH: {self.LD_LIBRARY_PATH}")

    def to_json(self):
        return {"LD_LIBRARY_PATH": self.LD_LIBRARY_PATH} if self.LD_LIBRARY_PATH else {}


class JVM_LD_LIBRARY_PATHEnvVar(ArgExtractor):
    """JVM_LD_LIBRARY_PATH"""

    @property
    def name(self):
        return "JVM_LD_LIBRARY_PATH"

    def extract(self, log_f, cmdline_args, env_vars):
        JVM_LD_LIBRARY_PATH = env_vars.get("JVM_LD_LIBRARY_PATH", None)
        if not os.path.isabs(JVM_LD_LIBRARY_PATH):
            JVM_LD_LIBRARY_PATH = os.path.join(env_vars["PWD"], JVM_LD_LIBRARY_PATH)
        self.JVM_LD_LIBRARY_PATH = JVM_LD_LIBRARY_PATH
        log_f(f"Extracted JVM_LD_LIBRARY_PATH: {self.JVM_LD_LIBRARY_PATH}")

    def to_json(self):
        return (
            {"JVM_LD_LIBRARY_PATH": self.JVM_LD_LIBRARY_PATH}
            if self.JVM_LD_LIBRARY_PATH
            else {}
        )


class ASAN_OPTIONSEnvVar(ArgExtractor):
    """ASAN_OPTIONS"""

    @property
    def name(self):
        return "ASAN_OPTIONS"

    def extract(self, log_f, cmdline_args, env_vars):
        self.ASAN_OPTIONS = env_vars.get("ASAN_OPTIONS", None)
        log_f(f"Extracted ASAN_OPTIONS: {self.ASAN_OPTIONS}")

    def to_json(self):
        return {"ASAN_OPTIONS": self.ASAN_OPTIONS} if self.ASAN_OPTIONS else {}


def javacrs_init_cp():
    global IN_COMPETITION

    CRS_TARGET = os.environ.get("CRS_TARGET")
    if IN_COMPETITION == "1":
        # In competition mode, standard path
        src_dir = "/src"
        out_dir = "/out"
    else:
        # In dev/evaluation, need run for multiple cps in parallel
        src_dir = f"/src-{os.path.basename(CRS_TARGET)}"
        out_dir = f"/out-{os.path.basename(CRS_TARGET)}"
    return CP(
        CRS_TARGET,
        f"{src_dir}/oss-fuzz/projects/{CRS_TARGET}",
        f"{src_dir}/repo",
        out_dir,
    )


class JavaCPMetadata:
    """Collections of heuristics retrieving metadata of a target CP."""

    def __init__(self, crs: CRS):
        self.crs = crs
        self.workdir = self.crs.workdir / "metadata" / self.crs.cp.name
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._prepare_meta()
        self._install_meta()

    def _set_full_src_dir(self):
        # TODO: Add non-focus proj path here?
        global IN_COMPETITION
        if IN_COMPETITION == "1":
            self.cp_full_src = Path("/src")
        else:
            # NOTE: In dev/evaluation, need run for multiple cps in parallel
            self.cp_full_src = Path(f"/src-{os.path.basename(self.cp_name)}")

    def _parse_package_from_file(self, file_path):
        with file_path.open("rb") as f:
            # Avoid heavier javalang if possible
            for line_bytes in f:
                try:
                    line = line_bytes.decode("utf-8", errors="ignore").strip()
                    if line.startswith("package "):
                        if line.endswith(";"):
                            # Get number of whitespaces and slashes in line
                            num_whitespaces = sum(1 for char in line if char.isspace())
                            num_slashes = sum(1 for char in line if char == "/")

                            if num_whitespaces == 1 and num_slashes == 0:
                                package_name = line.split(" ")[1].rstrip(";")
                                # Make sure there are no invalid characters in the package name
                                if all(
                                    char.isalnum() or char in ["_", "$", "."]
                                    for char in package_name
                                ):
                                    return package_name

                        # No need to check further if we are unable to parse the package
                        break
                except Exception:
                    continue

            # Fall back to javalang
            f.seek(0)
            file_content = f.read()
            try:
                tree = javalang.parse.parse(file_content)
                return tree.package.name
            except Exception:
                pass

        # In this case, we need to guess the package name from the file name.
        # It usually looks like this: **/src/*/*/com/package/ClassName.java.
        # We scan for the `src` directory and the first two directories after it.
        file_path_parts = file_path.parts
        src_index = file_path_parts.index("src") if "src" in file_path_parts else -1
        if src_index != -1 and len(file_path_parts) > src_index + 3:
            # Get the package name from the path
            package_name = ".".join(file_path_parts[src_index + 3 : -1])
            self.crs.log(
                f"{CRS_WARN} package name {package_name} is inferred from src path, check in which case this will happen (file: {file_path})"
            )
            return package_name.replace("/", ".")

        # No package name found, seek it as default pkg ""
        return ""

    def _infer_cp_pkg_list(self):
        self.crs.log(f"Inferring CP package list for {self.cp_name}")
        # pkg name -> set(files)
        pkg2files = {}

        for root, dirs, files in self.cp_full_src.walk(follow_symlinks=True):
            for file in files:
                try:
                    if file.endswith((".java", ".kt")):
                        jvm_file = Path(root) / file
                        pkg = self._parse_package_from_file(jvm_file)
                        pkg2files.setdefault(pkg, set()).add(str(jvm_file.resolve()))
                except Exception as e:
                    self.crs.log(
                        f"{CRS_ERR} Failed to parse package from file {file}: {e}, {traceback.format_exc()}"
                    )

        self.pkg_list = list(pkg2files.keys())
        self.pkg2files = pkg2files

    def _run_command(self, log_f, log_file, cmd, env, timeout, cwd=None) -> int:
        with open(log_file, "wb") as f:
            f.write(f"Running: {' '.join(cmd)}\n".encode())
            if cwd:
                f.write(f"Working directory: {cwd}\n".encode())

            process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd,
            )

            for line in process.stdout:
                f.write(line)

            try:
                exit_code = process.wait(timeout=timeout)
                f.write(f"\nExit code: {exit_code}\n".encode())
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = -1
                f.write(f"\nCommand timed out after {timeout} seconds\n".encode())

        log_f(f"Command completed, log saved to {log_file}")
        return exit_code

    def _infer_arg_n_env(self, workdir: Path, harness: CP_Harness, meta):
        try:
            output_json = workdir / "cpmeta-arg-env.json"
            env = os.environ.copy()
            env["MOCK_JAZZER_CPMETA_OUT"] = str(output_json.resolve())
            env["JAZZER_DIR"] = os.environ.get("ATL_MOCK_JAZZER_DIR")
            log_file_path = workdir / "run-arg-env-dump.log"
            log_file_path.parent.mkdir(parents=True, exist_ok=True)

            cmd = ["run_fuzzer", harness.name]
            ret = self._run_command(
                self.crs.log, log_file_path, cmd, env, timeout=300, cwd=None
            )
            self.crs.log(
                f"{CRS_ERR if ret != 0 else ""}_infer_arg_n_env run_fuzzer end with exit code {ret}"
            )

            if output_json.exists():
                meta.update(ArgExtractor.extract_all(self.crs.log, output_json))

        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} extracting metadata for {harness.name}: {e}, {traceback.format_exc()}"
            )

    def _parse_cpmetainfer_from_log(self, log_file_path):
        """Parse CPMETAINFER line from log file.
        -> CPMETAINFER#class_name#method_name#source_file
        """
        source_file, target_method = None, None

        try:
            if not log_file_path.exists():
                self.crs.log(f"{CRS_WARN} Log file not found: {log_file_path}")
                return source_file, target_method

            with open(log_file_path, errors="ignore") as f:
                for line in f:
                    if line.startswith("CPMETAINFER#"):
                        parts = line.strip().split("#")
                        if len(parts) >= 4:
                            target_method = parts[2].strip()
                            source_file = parts[3].strip()
        except Exception as e:
            self.crs.log(
                f"{CRS_WARN} Error when parsing CPMETAINFER from log: {e}, {traceback.format_exc()}"
            )

        if not source_file or not target_method:
            self.crs.log(
                f"{CRS_WARN} Failed to parse CPMETAINFER from log, source_file: {source_file}, target_method: {target_method}"
            )
        return source_file, target_method

    def _infer_src_basename(self, workdir, harness: CP_Harness, meta):
        beeps_dir = workdir / "src-basename-infer-beeps"
        beeps_dir.mkdir(parents=True, exist_ok=True)

        temp_cwd = Path(f"/tmp-cpmeta-{harness.name}-{uuid.uuid4().hex}")
        temp_cwd.mkdir(parents=True, exist_ok=True)
        self.crs.log(f"Created temporary directory for jazzer execution: {temp_cwd}")

        ATL_JAZZER_DIR = os.environ.get("ATL_JAZZER_DIR")
        jazzer_cmd = [
            "run_fuzzer",
            harness.name,
            f"--agent_path={ATL_JAZZER_DIR}/jazzer_standalone_deploy.jar",
            "--xcode",
            f"--beep_seed_dir={beeps_dir}",
            "-runs=0",
        ]

        env_vars = os.environ.copy()
        env_vars["JAZZER_DIR"] = ATL_JAZZER_DIR
        env_vars["ATLJAZZER_INFER_CPMETA_OUTPUT"] = "1"

        log_file_path = workdir / "src-basename-infer.log"

        try:
            ret = self._run_command(
                self.crs.log,
                log_file_path,
                jazzer_cmd,
                env_vars,
                timeout=120,
                cwd=str(temp_cwd),
            )
            self.crs.log(
                f"{CRS_WARN if ret != 0 else ''} src basename inference end with {ret}"
            )

        except Exception as e:
            warn_msg = f"{CRS_WARN} src basename inference met exp: {e} {traceback.format_exc()}"
            self.crs.log(warn_msg)

        basename_set = set()

        # Retrieve inferred info from log
        cpmetainfer_file, target_method = self._parse_cpmetainfer_from_log(
            log_file_path
        )
        if target_method and target_method not in ["", "null", "None"]:
            meta["target_method"] = target_method
        if cpmetainfer_file:
            basename_set.add(cpmetainfer_file)

        # Retrieve inferred info from cpmeta-*.json files
        cpmeta_files = glob.glob(str(beeps_dir / "cpmeta-*.json"))
        if not cpmeta_files:
            self.crs.log(f"{CRS_WARN} No cpmeta-*.json files found in {beeps_dir}")
        else:
            for cpmeta_file in cpmeta_files:
                try:
                    with open(cpmeta_file) as f:
                        cpmeta_data = json.load(f)
                        coord = cpmeta_data.get("coordinate", {})
                        file_name = coord.get("file_name")
                        if file_name:
                            basename_set.add(file_name)
                except Exception as e:
                    self.crs.log(
                        f"{CRS_WARN} Failed to process cpmeta file: {e}, {traceback.format_exc()}"
                    )

        basename_list = list(basename_set)
        self.crs.log(f"Combined basename_list: {basename_list}")
        return basename_list

    def _infer_path_frm_class_name(self, fully_qualified_name: str):
        if "$" in fully_qualified_name:
            top_level_class_name = fully_qualified_name.split("$", 1)[0]
        else:
            top_level_class_name = fully_qualified_name

        return top_level_class_name.replace(".", "/")

    def _transform_harness_src_path_for_Joern(self, src_path: Path) -> str:
        """Unify the src path to relative path to self.cp_fuzz_src, for Joern."""
        if str(src_path).startswith(str(self.proj_path)):
            return str(
                f"oss-fuzz/projects/{self.crs.cp.name}"
                / src_path.relative_to(self.proj_path)
            )
        elif str(src_path).startswith(str(self.repo_src_path)):
            return str("repo" / src_path.relative_to(self.repo_src_path))
        else:
            raise ValueError(f"Unknown harness src_path: {src_path}")

    def _infer_src_path(self, workdir, harness: CP_Harness, meta):
        src_paths = []
        try:
            basename_list = self._infer_src_basename(workdir, harness, meta)
            src_path_class_part = self._infer_path_frm_class_name(meta["target_class"])

            def match_fn(x):
                matched = False
                if len(basename_list) > 0:
                    for basename in basename_list:
                        if x.endswith(basename) and src_path_class_part in x:
                            matched = True
                            break
                else:
                    matched = x.endswith(f"{src_path_class_part}.java") or x.endswith(
                        f"{src_path_class_part}.kt"
                    )
                return matched

            for _, files in self.pkg2files.items():
                for file in files:
                    if match_fn(file):
                        src_paths.append(file)
        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to infer src basename for {harness.name}: {e}, {traceback.format_exc()}"
            )

        if len(src_paths) == 0:
            # try to find src path from harness name, find in self.cp_full_src
            for file in self.cp_full_src.glob(f"**/{harness.name}.java"):
                if file.is_file():
                    src_paths.append(str(file.resolve()))
            self.crs.log(
                f"{CRS_WARN} No src path found from package2files, trying to guess src path from harness name {harness.name}, found: {src_paths}"
            )

        if len(src_paths) >= 1:
            no_resources = [
                p
                for p in src_paths
                if "src/main/resources" not in p or "src/test/resources" not in p
            ]
            picked = (
                Path(no_resources[0]) if len(no_resources) > 0 else Path(src_paths[0])
            )
            meta["src_path"] = self._transform_harness_src_path_for_Joern(picked)
            self.crs.log(
                f"{CRS_WARN if len(src_paths) > 1 else ""} picked src path {picked} for {harness.name} from {len(src_paths)} src paths: {src_paths}"
            )
        else:
            self.crs.log(f"{CRS_ERR} No src path found for {harness.name}")

    def _infer_ossdict_path(self, harness: CP_Harness, meta: dict, opt_dict_value: str):
        try:
            bin_path = harness.bin_path
            dict_path = None
            if opt_dict_value is not None:
                # search based on the basename of opt_dict_value and dir of bin_path
                dict_path = bin_path.parent / opt_dict_value

            if dict_path is None or not dict_path.exists():
                dict_path = bin_path.with_suffix(".dict")

            if not dict_path.exists():
                return
            meta["ossdict_path"] = str(dict_path.resolve())
        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to infer ossdict path for {harness.name}: {e}, {traceback.format_exc()}"
            )
            return

    def _infer_options(self, harness: CP_Harness, meta: dict):
        options = {}
        opt_dict_value = None

        try:
            options_path = harness.bin_path.with_suffix(".options")
            if options_path.exists():
                parser = configparser.ConfigParser()
                parser.read(options_path)
                for section in parser.sections():
                    options[section] = {}
                    for key, value in parser.items(section):
                        options[section][key] = value
                        if key == "dict":
                            opt_dict_value = value

                meta["options_path"] = str(options_path.resolve())
                meta["options"] = options

        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to parse options file {options_path}: {e}, {traceback.format_exc()}"
            )

        self._infer_ossdict_path(harness, meta, opt_dict_value)

    def _infer_osscorpus(self, workdir: Path, harness: CP_Harness, meta: dict):
        try:
            bin_path = harness.bin_path
            bin_basename = bin_path.name
            osscorpus_zip_path = bin_path.parent / f"{bin_basename}_seed_corpus.zip"
            if osscorpus_zip_path.exists():
                meta["osscorpus_zip_path"] = str(osscorpus_zip_path.resolve())
                # unzip to workdir/osscorpus (unzip -o -d)
                osscorpus_path = workdir / "osscorpus"
                osscorpus_path.mkdir(parents=True, exist_ok=True)
                self.crs.log(
                    f"Unzipping {osscorpus_zip_path} to {osscorpus_path} for harness {harness.name}"
                )
                unzip_sync(osscorpus_zip_path, osscorpus_path, CRS_ERR)
                meta["osscorpus_path"] = str(osscorpus_path.resolve())
        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to infer osscorpus for {harness.name}: {e}, {traceback.format_exc()}"
            )

    def _infer_harness_meta(self, harness: CP_Harness):
        workdir = self.workdir / harness.name
        workdir.mkdir(parents=True, exist_ok=True)

        meta = {
            "name": harness.name,
            "bin_path": str(harness.bin_path.resolve()),
            # Default target method, will be overridden if we can infer it
            "target_method": "fuzzerTestOneInput",
            # NOTE: we didn't infer this till now
            # "target_method_desc": "([B)V",
        }

        self._infer_options(harness, meta)
        self._infer_osscorpus(workdir, harness, meta)
        self._infer_arg_n_env(workdir, harness, meta)
        self._infer_src_path(workdir, harness, meta)

        harness.src_path = Path(meta["src_path"]) if meta.get("src_path") else None
        return meta

    def _infer_harnesses_meta(self):
        self.harnesses = {}
        for harness in self.crs.target_harnesses:
            self.harnesses[harness.name] = self._infer_harness_meta(harness)

    def _prepare_meta(self):
        # N.B. cp_name can have / in oss-fuzz, e.g., aixcc/jvm/jenkins
        self.cp_name = self.crs.cp.name
        self.proj_path = self.crs.cp.proj_path
        self.repo_src_path = self.crs.cp.cp_src_path
        self.built_path = self.crs.cp.built_path
        self.ref_diff_path = self.crs.cp.diff_path
        self.custom_sink_conf = self.crs.sinkmanager.get_custom_sink_conf_path()
        self.sinkpoint_path = self.workdir / "sinkpoints.json"
        self._set_full_src_dir()
        self._infer_cp_pkg_list()
        self._infer_harnesses_meta()

    def _dump_meta(self):
        try:
            self.meta_path = self.workdir / "cpmeta.json"
            self.meta_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(
                {
                    "cp_name": self.cp_name,
                    "proj_path": str(self.proj_path.resolve()),
                    "repo_src_path": str(self.repo_src_path.resolve()),
                    "ref_diff_path": (
                        str(self.ref_diff_path.resolve()) if self.ref_diff_path else ""
                    ),
                    "custom_sink_conf": str(self.custom_sink_conf.resolve()),
                    "sinkpoint_path": str(self.sinkpoint_path.resolve()),
                    "built_path": str(self.built_path.resolve()),
                    "cp_full_src": str(self.cp_full_src.resolve()),
                    "harnesses": self.harnesses,
                    "pkg2files": {k: list(s) for k, s in self.pkg2files.items()},
                },
                indent=2,
                sort_keys=True,
            )

            atomic_write_file_sync(self.meta_path, content)
            checksum = hashlib.sha256(content.encode()).hexdigest()
            share_path = get_crs_java_share_cpmeta_path(checksum)
            if share_path is not None:
                atomic_write_file_sync(share_path, content)
                self.crs.log(f"Copied cpmeta.json to {share_path} with md5 checksum")
            else:
                self.crs.log(
                    f"{CRS_ERR} Failed to copy cpmeta.json to share dir since share_path is {share_path}"
                )
        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to dump metadata for {self.cp_name}: {e}, {traceback.format_exc()}"
            )

    def _generate_aixcc_config(self):
        """Generate .aixcc/config.yaml for deepgen module"""
        try:
            aixcc_dir = self.proj_path / ".aixcc"
            aixcc_dir.mkdir(parents=True, exist_ok=True)

            harness_files = []
            for harness_name, harness_info in self.harnesses.items():
                if "src_path" not in harness_info:
                    self.crs.log(
                        f"{CRS_WARN} No src_path for harness {harness_name}, skipping"
                    )
                    continue

                full_src_path = self.cp_full_src / harness_info["src_path"]
                if str(full_src_path).startswith(str(self.proj_path)):
                    path_prefix = "$PROJECT"
                    relative_path = full_src_path.relative_to(self.proj_path)
                elif str(full_src_path).startswith(str(self.repo_src_path)):
                    path_prefix = "$REPO"
                    relative_path = full_src_path.relative_to(self.repo_src_path)
                else:
                    self.crs.log(
                        f"{CRS_WARN} Unexpected src_path format: {full_src_path}"
                    )
                    continue

                harness_files.append(
                    {"name": harness_name, "path": f"{path_prefix}/{relative_path}"}
                )

            config = {"harness_files": harness_files}
            config_path = aixcc_dir / "config.yaml"
            with open(config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            self.crs.log(
                f"Generated .aixcc/config.yaml to {config_path} with {len(harness_files)} harness entries"
            )
        except Exception as e:
            self.crs.log(
                f"{CRS_ERR} Failed to generate .aixcc/config.yaml: {e}, {traceback.format_exc()}"
            )

    def _install_initial_corpus(self):
        for harness_id, meta in self.harnesses.items():
            try:
                initial_corpus = self.workdir / harness_id / "initial-corpus"
                initial_corpus.mkdir(parents=True, exist_ok=True)
                osscorpus_path = meta.get("osscorpus_path", None)
                if osscorpus_path is not None and os.path.exists(osscorpus_path):
                    try:
                        succ, fail = flatten_dir_copy_sync(
                            Path(osscorpus_path), initial_corpus, self.crs.log
                        )
                        self.crs.log(
                            f"{CRS_WARN if fail > 0 else ""} Copied initial corpus from {osscorpus_path} to {initial_corpus}, success: {succ}, fail: {fail}"
                        )
                    except Exception as e:
                        self.crs.log(
                            f"{CRS_ERR} Failed to copy initial corpus for {harness_id}: {e}, {traceback.format_exc()}"
                        )
                crs_multilang_nfs_path = get_crs_multilang_nfs_seedshare_dir(harness_id)
                if crs_multilang_nfs_path is not None:
                    try:
                        succ, fail = flatten_dir_copy_sync(
                            crs_multilang_nfs_path, initial_corpus, self.crs.log
                        )
                        self.crs.log(
                            f"{CRS_WARN if fail > 0 else ''} Copied initial corpus from NFS share {crs_multilang_nfs_path} to {initial_corpus}, success: {succ}, fail: {fail}"
                        )
                    except Exception as e:
                        self.crs.log(
                            f"{CRS_ERR} Failed to copy initial corpus from NFS for {harness_id}: {e}, {traceback.format_exc()}"
                        )
                crs_java_nfs_path = get_crs_java_nfs_seedshare_dir(harness_id)
                if crs_java_nfs_path is not None:
                    try:
                        succ, fail = flatten_dir_copy_sync(
                            crs_java_nfs_path, initial_corpus, self.crs.log
                        )
                        self.crs.log(
                            f"{CRS_WARN if fail > 0 else ''} Copied initial corpus from NFS share {crs_java_nfs_path} to {initial_corpus}, success: {succ}, fail: {fail}"
                        )
                    except Exception as e:
                        self.crs.log(
                            f"{CRS_ERR} Failed to copy initial corpus from NFS for {harness_id}: {e}, {traceback.format_exc()}"
                        )
            except Exception as e:
                self.crs.log(
                    f"{CRS_ERR} Failed to install initial corpus for harness {harness_id}: {e}, {traceback.format_exc()}"
                )

    def _install_meta(self):
        """
        libCRS has already setup env vars:
          - CRS_WORKDIR
          - TARGET_CP <- CRS_TARGET
          - CP_PROJ_PATH <- proj_path (/src-xxx/oss-fuzz/projects/xxx)
          - CP_SRC_PATH <- repo_src_path (/src-xxx/repo)
        """
        self._dump_meta()
        self._generate_aixcc_config()
        self._install_initial_corpus()

        os.environ["CP_BUILD_PATH"] = str(self.built_path.resolve())
        os.environ["CP_FULL_SRC"] = str(self.cp_full_src.resolve())
        os.environ["CP_REF_DIFF_FILE"] = (
            str(self.ref_diff_path.resolve()) if self.ref_diff_path else ""
        )
        os.environ["CP_SINKPOINTS_FILE"] = str(self.sinkpoint_path.resolve())
        os.environ["CP_METADATA_FILE"] = str(self.meta_path.resolve())
        os.environ["CP_CUSTOM_SINK_CONF"] = str(self.custom_sink_conf.resolve())
        os.environ["DEEPGEN_TASK_REQ_DIR"] = str(
            self.crs.deepgen.get_task_req_dir().resolve()
        )

    def is_diff_mode(self) -> bool:
        return self.ref_diff_path is not None

    def get_ref_diff_path(self) -> Path:
        return self.ref_diff_path

    def get_custom_sink_conf_path(self) -> Path:
        return self.custom_sink_conf

    def get_harness_rss_limit_mb(self, harness: CP_Harness) -> int | None:
        v = (
            self.harnesses[harness.name]
            .get("options", {})
            .get("libfuzzer", {})
            .get("rss_limit_mb", None)
        )
        if v is not None:
            try:
                return int(v)
            except ValueError:
                self.crs.log(
                    f"{CRS_ERR} Invalid rss_limit_mb value for harness {harness.name}: {v}"
                )
        return None

    def get_harness_len_control(self, harness: CP_Harness) -> int | None:
        v = (
            self.harnesses[harness.name]
            .get("options", {})
            .get("libfuzzer", {})
            .get("len_control", None)
        )
        if v is not None:
            try:
                return int(v)
            except ValueError:
                self.crs.log(
                    f"{CRS_ERR} Invalid len_control value for harness {harness.name}: {v}"
                )
        return None

    def get_harness_max_len(self, harness: CP_Harness) -> int | None:
        v = (
            self.harnesses[harness.name]
            .get("options", {})
            .get("libfuzzer", {})
            .get("max_len", None)
        )
        if v is not None:
            try:
                return int(v)
            except ValueError:
                self.crs.log(
                    f"{CRS_ERR} Invalid max_len value for harness {harness.name}: {v}"
                )
        return None

    def get_harness_timeout_exitcode(self, harness: CP_Harness) -> int | None:
        v = (
            self.harnesses[harness.name]
            .get("options", {})
            .get("libfuzzer", {})
            .get("timeout_exitcode", None)
        )
        if v is not None:
            try:
                return int(v)
            except ValueError:
                self.crs.log(
                    f"{CRS_ERR} Invalid timeout_exitcode value for harness {harness.name}: {v}"
                )
        return None

    def get_harness_ASAN_OPTIONS(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name].get("ASAN_OPTIONS", "")

    def get_harness_initial_corpus_path(self, harness: CP_Harness) -> Path:
        return self.workdir / harness.name / "initial-corpus"

    def get_harness_osscorpus_path(self, harness: CP_Harness) -> str | None:
        return self.harnesses[harness.name].get("osscorpus_path", None)

    def get_harness_ossdict_path(self, harness: CP_Harness) -> str | None:
        return self.harnesses[harness.name].get("ossdict_path", None)

    def get_harness_entrypoint(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name]["target_method"]

    def get_harness_src_path(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name]["src_path"]

    def get_harness_class(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name]["target_class"]

    def get_harness_classpath(self, harness: CP_Harness) -> [str]:
        return self.harnesses[harness.name]["classpath"]

    def get_harness_JAVA_HOME(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name].get("JAVA_HOME", "")

    def get_harness_LD_LIBRARY_PATH(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name].get("LD_LIBRARY_PATH", "")

    def get_harness_JVM_LD_LIBRARY_PATH(self, harness: CP_Harness) -> str:
        return self.harnesses[harness.name].get("JVM_LD_LIBRARY_PATH", "")

    def get_merged_classpath(self) -> [str]:
        classpath = set()
        for harness in self.harnesses.values():
            classpath.update(harness["classpath"])
        return list(classpath)
