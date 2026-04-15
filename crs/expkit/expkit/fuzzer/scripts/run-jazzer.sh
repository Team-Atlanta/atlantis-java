#!/bin/bash

# Exit on any error
set -x
#set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "This fuzzer is bound to cpu ${FUZZ_BOUND_CPULIST}"

# Usage check
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <JAZZER_DIR> <WORK_DIR>"
    exit 1
fi

#
# Input Args
#
JAZZER_DIR="$1"
WORK_DIR="$2"

# fuzzing opts
N_KEEP_GOING=5000

#
# Jazzer directories and files setup
#
ARTIFACT_DIR=${WORK_DIR}/artifacts
REPRODUCER_DIR=${WORK_DIR}/reproducer
CORPUS_DIR=${WORK_DIR}/corpus_dir
DICT_FILE=${WORK_DIR}/fuzz.dict
FUZZ_LOG=${WORK_DIR}/fuzz.log
RESULT_JSON=${WORK_DIR}/result.json

mkdir -p "${ARTIFACT_DIR}"
mkdir -p "${REPRODUCER_DIR}"
mkdir -p "${CORPUS_DIR}"

if [[ "$JAZZER_DIR" = "${AIXCC_JAZZER_DIR}" ]]; then
  CLOSE_FD_OPT=" "
else
  CLOSE_FD_OPT="-close_fd_mask=1 "
fi

echo "Create a placeholder in case that is an empty/non-exist dict to make Jazzer happy"
echo "# PLACEHOLDER" >> "${DICT_FILE}"

export JAZZER_ARTIFACT_DIR="${ARTIFACT_DIR}"

#
# Kick off the fuzzer
#
cat > "${WORK_DIR}/_run_fuzzer_timeout_stub.sh" <<EOF
while true
do

  export ATLJAZZER_CUSTOM_SINKPOINT_CONF=${FUZZ_CUSTOM_SINK_CONF}
  export CORPUS_DIR="${CORPUS_DIR}"
  export JAZZER_DIR="${JAZZER_DIR}"

  if [[ -f ${CORPUS_DIR}/poc ]]; then
    echo "Try validate the poc before doing anything else"
    export SKIP_SEED_CORPUS=1
    stdbuf -e 0 -o 0 \
      run_fuzzer ${FUZZ_TARGET_HARNESS} \
        -runs=100 \
        "\$@" \
        ${CORPUS_DIR}/poc || echo @@@@@ exit code of Jazzer is $? @@@@@ >&2
    unset SKIP_SEED_CORPUS
  fi

  if [[ -n \${FUZZ_VERIFY_ONLY} ]]; then
    echo "FUZZ_VERIFY_ONLY is set, skip fuzzing"
    sleep 1s
    break
  fi

  stdbuf -e 0 -o 0 \
    run_fuzzer ${FUZZ_TARGET_HARNESS} \
      "\$@" || echo @@@@@ exit code of Jazzer is $? @@@@@ >&2

  # Clean up!
  rm -rf ${DIRECTED_CLASS_DUMP_DIR}
  mkdir -p ${DIRECTED_CLASS_DUMP_DIR}

  sleep 1s

done
EOF
chmod +x ${WORK_DIR}/_run_fuzzer_timeout_stub.sh

timeout -s SIGKILL ${FUZZ_TTL_FUZZ_TIME}s \
  taskset -c ${FUZZ_BOUND_CPULIST} \
    stdbuf -e 0 -o 0 \
      bash ${WORK_DIR}/_run_fuzzer_timeout_stub.sh \
        --reproducer_path="${REPRODUCER_DIR}" \
        --agent_path=${JAZZER_DIR}/jazzer_standalone_deploy.jar \
        --keep_going="${N_KEEP_GOING}" \
        -artifact_prefix="${ARTIFACT_DIR}/" \
        ${FUZZ_CUSTOM_ARGS} \
        ${CLOSE_FD_OPT} \
        -reload=30 \
        -max_len=1048576 \
        -len_control=0 \
        -max_total_time="${FUZZ_TTL_FUZZ_TIME}" \
        -dict="${DICT_FILE}" \
        -keep_seed=1 2>&1 | \
      stdbuf -e 0 -o 0 ts "%s" | \
      python3.12 -u ${SCRIPT_DIR}/jazzer_postprocessing.py -o ${RESULT_JSON} --rolling-log ${FUZZ_LOG} || true
