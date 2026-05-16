#!/usr/bin/env python3

import os
import shutil
import subprocess
from pathlib import Path

OSS_FUZZ_PROJ_DIR = Path(os.getenv("OSS_CRS_PROJ_PATH", "/OSS_CRS_PROJ_PATH"))
CRS_PROJ_DIR = Path("/out/crs/proj")
OSS_SRC_DIR = Path(os.getenv("SRC", "/src"))
CRS_SRC_DIR = Path("/out/crs/src")
CRS_CODEQL_DB_DIR = Path("/out/crs/codeql-db")


def build_and_create_codeql_database():
    """Run OSS-Fuzz compile under CodeQL trace.

    This both builds the target (jars, fuzz harnesses → /out) and creates the
    CodeQL database, in a single invocation. Running compile twice (once normally,
    once under trace) would cause Maven to skip recompilation on the second run,
    leaving the CodeQL database with stub-only classes.
    """
    print(f"Creating CodeQL database from {OSS_SRC_DIR}")
    if CRS_CODEQL_DB_DIR.exists():
        shutil.rmtree(CRS_CODEQL_DB_DIR)

    result = subprocess.run(
        [
            "codeql", "database", "create",
            str(CRS_CODEQL_DB_DIR),
            "--language=java",
            f"--source-root={OSS_SRC_DIR}",
            "--command=/usr/local/bin/compile",
            "--overwrite",
        ],
        check=True,
    )

    if CRS_CODEQL_DB_DIR.exists():
        print(f"CodeQL database created at {CRS_CODEQL_DB_DIR}")
    else:
        print(f"WARNING: CodeQL database creation failed (ret={result.returncode})")


def prepare_crs_src():
    if CRS_SRC_DIR.exists():
        shutil.rmtree(CRS_SRC_DIR)
    shutil.copytree(OSS_FUZZ_PROJ_DIR, CRS_PROJ_DIR, symlinks=True)
    shutil.copytree(OSS_SRC_DIR, CRS_SRC_DIR, symlinks=True)


def submit_build_outputs():
    """Submit build outputs to oss-crs framework via libCRS."""
    subprocess.run(["libCRS", "submit-build-output", "/out", "build"], check=True)
    subprocess.run(["libCRS", "submit-build-output", str(CRS_PROJ_DIR), "crs/proj"], check=True)
    subprocess.run(["libCRS", "submit-build-output", str(CRS_SRC_DIR), "crs/src"], check=True)
    if CRS_CODEQL_DB_DIR.exists():
        subprocess.run(["libCRS", "submit-build-output", str(CRS_CODEQL_DB_DIR), "crs/codeql-db"], check=True)


def main():
    build_and_create_codeql_database()
    prepare_crs_src()
    submit_build_outputs()


if __name__ == "__main__":
    main()
