#!/bin/bash

#set -e

setup_src_proj() {
    src_proj=/src/oss-fuzz/projects/$CRS_TARGET
    mkdir -p $src_proj
    rsync -a --delete /out/crs/proj/ $src_proj/
    mkdir -p $src_proj/.aixcc/
}

setup_src_repo() {
    src_repo=/src/repo
    mkdir -p $src_repo
    rsync -a --delete /out/crs/src/ $src_repo/
}

setup_out() {
    out_dir=/out
    # TODO: Check this before every AFC submission
    # Ref: https://github.com/aixcc-finals/oss-fuzz-aixcc/blob/aixcc-afc/infra/base-images/base-builder/compile#L180
    find $out_dir -type f | while read f;
    do
      if [[ $(basename "$f") =~ ^jazzer.*$ ]]; then
        if [[ "$basename" != "jazzer_driver_with_sanitizer" ]]; then
          rm -f "$f"
        fi
      fi
    done
    rsync -a $JAVA_CRS_SRC/jazzer_driver_stub $out_dir/jazzer_driver
}

setup_cp_dirs() {
    setup_src_proj
    setup_src_repo
    setup_out
}

validate_target_harness() {
    if [ -z "$1" ]; then
        echo "ERROR: TARGET_HARNESS argument is required"
        echo "Usage: $0 <target_harness>"
        exit 1
    fi
    export TARGET_HARNESS="$1"
    echo "Target harness set to: $TARGET_HARNESS"
}

update_crs_cfg() {
    DEFAULT_CFG="$JAVA_CRS_SRC/crs-java.config"
    python3.12 javacrscfg.py merge-crs-cfg "$DEFAULT_CFG"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to update CRS configuration"
        exit 1
    fi
}

run_crs() {
    pushd $JAVA_CRS_SRC > /dev/null

    export JAVA_CRS_IN_COMPETITION=1
    export CRS_JAVA_POD_NAME=local
    export CRS_JAVA_POD_NAMESPACE=local
    export FUZZING_ENGINE=libfuzzer
    # TODO: this should always be the case? (how about coverage, etc)
    export SANITIZER=${SANITIZER:-address}
    export HELPER=True
    export RUN_FUZZER_MODE=interactive
    export SEED_SHARE_DIR="/seed-shared-`basename $CRS_TARGET`"
    export SARIF_SHARE_DIR="/sarif-shared-`basename $CRS_TARGET`"
    export SARIF_ANA_RESULT_DIR="/sarif-ana-result-`basename $CRS_TARGET`"
    export SARIF_REACHABILIY_SHARE_DIR="/sarif-reachability-shared-`basename $CRS_TARGET`"
    export CRS_JAVA_SHARE_DIR="/crs-java-shared-`basename $CRS_TARGET`"
    export CRS_JAVA_TEST_ENV_ROLE="leader"
    export TARBALL_FS_DIR="/tarball-fs"
    export CRS_WORKDIR=/out/crs-workdir
    export OSS_CRS_ARTIFACT_CORPUS="/artifacts/corpus"
    export OSS_CRS_ARTIFACT_POV="/artifacts/povs"

    update_crs_cfg

    mkdir -p $CRS_WORKDIR/worker-0
    python3.12 -u ./main.py $DEFAULT_CFG 2>&1 | tee $CRS_WORKDIR/worker-0/crs-java.log

    popd > /dev/null
}

setup_llm() {
    # Setup LiteLLM URL
    if [ -n "$LITELLM_URL" ]; then
        export AIXCC_LITELLM_HOSTNAME="$LITELLM_URL"
        echo "Using provided LITELLM_URL: $LITELLM_URL"
    else
        export LITELLM_URL="http://litellm:4000"
        export AIXCC_LITELLM_HOSTNAME="http://litellm:4000"
        echo "Using default LITELLM_URL: http://litellm:4000"
    fi

    # Setup LiteLLM API key (priority: /keys/api_key > env LITELLM_KEY > fake-key)
    if _key=$(cat /keys/api_key 2>/dev/null); then
        export LITELLM_KEY="$_key"
        echo "LITELLM_KEY retrieved successfully from /keys/api_key"
    elif [ -n "$LITELLM_KEY" ]; then
        echo "Using provided LITELLM_KEY from environment"
    else
        export LITELLM_KEY="fake-key"
        echo "WARNING: No LiteLLM key found, using fake-key as fallback"
    fi
}

setup_sys() {
    ulimit -c 0
    sysctl -w fs.file-max=2097152
}

validate_target_harness "$1"
setup_llm
setup_cp_dirs
setup_sys
run_crs
