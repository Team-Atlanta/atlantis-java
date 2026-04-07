# CRS-java Dev Guide

This guide is for running the Atlantis-Java CRS locally (without OSS-CRS), mostly for debugging purposes.

- 1. Set up [./crs/crs-java.config](./crs/crs-java.config) according to [docs](./docs/javacrscfg.schema.md).
- 2. Use `dev.sh` to build, run, develop the CRS.

## Dev Usage

```bash
# build CP(s)
./dev.sh build-cp '<target-list>' '<cp-name-regex>'
# e.g., ./dev.sh build-cp cps "aixcc/jvm/*"

# build CRS image
./dev.sh build-crs

# run CRS on target CP according to `crs/crs-java.config`
LITELLM_KEY=xxx CRS_TARGET=aixcc/jvm/fuzzy ./dev.sh run

# clean
./dev.sh clean

# DEV mode, (host `./crs` mount to container)
DEV=1 LITELLM_KEY=xxx ./dev.sh custom sleep infinity
# Get a shell, docker exec -it ...
## inside container
## - specify a target
CRS_TARGET=aixcc/jvm/fuzzy ./dev-run.sh ...
## - interactively pick a target
./dev-run.sh ...
## - or do anything u want

# install yq dependency
./dev.sh install-yq

# update CRS config documentation
# pip3 install jsonschema-markdown
./dev.sh gen-doc

# run crs e2e functionality test
LITELLM_KEY=xxx ./dev.sh test aixcc/jvm/mock-java OssFuzz1 [CRS_TTL_TIME] [true]

# run coverage reproduction mode
# REPRO should be a directory containing HarnessRunner/**/fuzz directories
# REPRO_PARA controls parallelism (default 1)
REPRO=/path/to/repro/dir REPRO_PARA=4 ./dev.sh run
```

## JavaCRS key variables or files

- [Benchmark CP list](./targets.yaml)
- [Configuration doc](./docs/javacrscfg.schema.md)
- [Source code intro](./crs/README.md)
- [atl-jazzer feature list](./crs/fuzzers/README.md)
- Development mode: `DEV=1 bash dev.sh ...`
  - Using [development profile](./compose.dev.yaml) such as mounting crs code into container
- Coverage reproduction mode: `REPRO=/path/to/dir REPRO_PARA=4 bash dev.sh run`
  - The REPRO directory should contain fuzzing results with pattern `HarnessRunner/**/fuzz`
  - Each fuzz directory should have subdirectories with `corpus_dir` containing the corpus to reproduce
  - The mode will automatically extract CP names, setup environments, and generate coverage results
  - A `repro` subdirectory will be created under each fuzz directory containing `result.json` and `fuzz.log` after analysis
  - `REPRO_PARA` controls the parallelism for processing multiple fuzz directories (default: 1)
- **Inside CRS container**, some key ENV variables
  - `JAVA_CRS_SRC` -> default value `/app/crs-cp-java`, crs code directory, mapping to `./crs` if `DEV` is set
  - `CP_PROJ_PATH` -> CP project path in `oss-fuzz`, e.g., `oss-fuzz/projects/PROJ`
  - `CP_SRC_PATH` -> CP project repo source path in `oss-fuzz`, e.g., `oss-fuzz/build/repos/PROJ`
  - `LITELLM_KEY` -> required for running JavaCRS
  - `CRS_TARGET` -> required for running JavaCRS, inherited from `libCRS`, so CRS solve one target CP (one or multiple harnesses) per run
  - `CRS_JAVA_COV_REPRO` -> set when REPRO env is provided, triggers coverage reproduction mode
  - `CRS_JAVA_COV_REPRO_PARA` -> parallelism for coverage reproduction (from REPRO_PARA env, default: 1)

## Setup pre-commit for auto code-check

Check `.pre-commit-config.yaml` for your code and taste, then:

```
# install pre-commit
apt install pre-commit
# install into .git/hooks
pre-commit install
# manually trigger
# need install deps like ruby, gem, etc, follow error info
pre-commit run
```
