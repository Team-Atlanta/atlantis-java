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

#
# Jazzer directories and files setup
#
ARTIFACT_DIR=${WORK_DIR}/artifacts
REPRODUCER_DIR=${WORK_DIR}/reproducer
CORPUS_DIR=${WORK_DIR}/corpus_dir
BEEPSEED_DIR=${WORK_DIR}/beeps
DIRECTED_CLASS_DUMP_DIR=${WORK_DIR}/directed_class_dump
DICT_FILE=${WORK_DIR}/fuzz.dict
FUZZ_LOG=${WORK_DIR}/fuzz.log
RESULT_JSON=${WORK_DIR}/result.json
CLEANER_SCRIPT=${SCRIPT_DIR}/cleaner.py
OTEL_LOG_SCRIPT=${SCRIPT_DIR}/otel_log.py
CLEANER_LOG=${WORK_DIR}/cleaner.log
COV_EXEC_FILE=${WORK_DIR}/jacoco.exec

mkdir -p "${ARTIFACT_DIR}"
mkdir -p "${REPRODUCER_DIR}"
mkdir -p "${CORPUS_DIR}"
mkdir -p "${BEEPSEED_DIR}"
mkdir -p "${DIRECTED_CLASS_DUMP_DIR}"

echo "Create a placeholder in case that is an empty/non-exist dict to make Jazzer happy"
echo "# PLACEHOLDER" >> "${DICT_FILE}"

export JAZZER_ARTIFACT_DIR="${ARTIFACT_DIR}"

#
# BEEP seed searching option
#
if [[ "${FUZZ_BEEPSEED_SEARCH}" = "on" ]]; then
  echo "FUZZ_BEEPSEED_SEARCH is on, enabling codemarker to search BEEP seed"
  BEEPSEED_OPTS="--xcode --beep_seed_dir=${BEEPSEED_DIR} "
else
  BEEPSEED_OPTS=""
  echo "FUZZ_BEEPSEED_SEARCH is off, not enabling codemarker"
fi

#
# Directed fuzzing option
#
if [[ ! -z "${FUZZ_DIRECTED_TGT_PATH}" ]]; then
  echo "FUZZ_DIRECTED_TGT_PATH is set, setting directed fuzzing options"
  DIRECTED_FUZZING_ARGS="--directed_fuzzing_distances=${FUZZ_DIRECTED_TGT_PATH} "

  # Add optional timing arguments for directed mode
  if [[ ! -z "${FUZZ_DIRECTED_EXPLORE_TIME}" ]]; then
    DIRECTED_FUZZING_ARGS+="-entropic_exploration_time=${FUZZ_DIRECTED_EXPLORE_TIME} "
  fi
  if [[ ! -z "${FUZZ_DIRECTED_TIME}" ]]; then
    DIRECTED_FUZZING_ARGS+="-entropic_directed_time=${FUZZ_DIRECTED_TIME} "
  fi

  # Explicitly specify the dump class directory to prevent it randomly creates files under /tmp
  DIRECTED_FUZZING_ARGS+="--dump_classes_dir=${DIRECTED_CLASS_DUMP_DIR} "

else
  echo "FUZZ_DIRECTED_TGT_PATH is empty, there is no directed fuzzing setting"
  DIRECTED_FUZZING_ARGS=""

  # Warn if timing arguments are set when directed mode is off
  if [[ ! -z "${FUZZ_DIRECTED_EXPLORE_TIME}" ]] || [[ ! -z "${FUZZ_DIRECTED_TIME}" ]]; then
    echo "WARN: FUZZ_DIRECTED_EXPLORE_TIME and FUZZ_DIRECTED_TIME are ignored when directed fuzzing is disabled"
  fi

fi

#
# Other fuzzing options
#
if [[ ! -z "${FUZZ_LEN_CONTROL}" ]]; then
  echo "FUZZ_LEN_CONTROL is set to ${FUZZ_LEN_CONTROL}, setting length control option"
  EXP_SEED_LEN_OPTS="-len_control=${FUZZ_LEN_CONTROL} "
else
  echo "FUZZ_LEN_CONTROL is not set, no len control"
  EXP_SEED_LEN_OPTS+="-len_control=0 "
fi
if [[ ! -z "${FUZZ_MAX_LEN}" ]]; then
  echo "FUZZ_MAX_LEN is set to ${FUZZ_MAX_LEN}, setting max length option"
  EXP_SEED_LEN_OPTS+="-max_len=${FUZZ_MAX_LEN} "
else
  echo "FUZZ_MAX_LEN is not set, let libfuzzer infer seed max length"
fi
if [[ "${FUZZ_KEEP_SEED}" = "on" ]]; then
  echo "FUZZ_KEEP_SEED is on, keeping seed"
  KEEP_SEED_OPT="-keep_seed=1 "
else
  echo "FUZZ_KEEP_SEED is off, not keeping seed"
  KEEP_SEED_OPT="-keep_seed=0 "
fi
N_KEEP_GOING_OPT="--keep_going=5000 "

#
# JaCoCo coverage dump option
#
if [[ ! -z "${JACOCO_COV_DUMP_PERIOD}" ]]; then
  echo "JACOCO_COV_DUMP_PERIOD is set to ${JACOCO_COV_DUMP_PERIOD}, setting coverage dump option"
  COVERAGE_DUMP_OPT="--coverage_dump=${COV_EXEC_FILE} "
else
  echo "JACOCO_COV_DUMP_PERIOD is not set, no coverage dump"
  COVERAGE_DUMP_OPT=""
fi

if [[ "${FUZZ_MERGE_SEED}" = "on" ]]; then

if [[ -d "${FUZZ_INITIAL_CORPUS}" ]]; then
  # rsync the initial corpus to the corpus dir
  echo "FUZZ_INITIAL_CORPUS is set, rsyncing ${FUZZ_INITIAL_CORPUS} to ${FUZZ_MERGE_FROM_RAW_DIR}"
  rsync -a --ignore-existing "${FUZZ_INITIAL_CORPUS}/" "${FUZZ_MERGE_FROM_RAW_DIR}/"
else
  echo "FUZZ_INITIAL_CORPUS is not set, corpus dir will be empty at the beginning"
fi

FUZZ_MERGE_TO_DIR=${CORPUS_DIR}
FUZZ_MERGE_TO_DIR_COVONLY=${CORPUS_DIR}-covonly
mkdir -p "${FUZZ_MERGE_TO_DIR_COVONLY}"

if [[ "${FUZZ_SET_COVER_MERGE}" = "on" ]]; then
  echo "FUZZ_SET_COVER_MERGE is on, setting up cover merge directories"
  FUZZ_MERGE_OPT="-merge=1 -set_cover_merge=1 "
else
  echo "FUZZ_SET_COVER_MERGE is off, not setting up cover merge directories"
  FUZZ_MERGE_OPT="-merge=1 "
fi

if [[ "$JAZZER_DIR" = "${AIXCC_JAZZER_DIR}" ]]; then
  CLOSE_FD_OPT=" "
else
  CLOSE_FD_OPT="-close_fd_mask=1 "
fi

#
# Kick off the fuzzer
#
cat > "${WORK_DIR}/_run_fuzzer_timeout_stub.sh" <<EOF
#!/bin/bash
#set -x

# NOTE: @cen, yes, this is a bit hacky and not the best place to invoke the cleaner, but it works
# Setup cleaner for the /tmp
python3.12 -u ${CLEANER_SCRIPT} > ${CLEANER_LOG} 2>&1 &
CLEANER_PID=\$!

cleanup() {
  python3 ${OTEL_LOG_SCRIPT} "Cleaning up cleaner process (PID: \$CLEANER_PID)"
  kill \$CLEANER_PID
  wait \$CLEANER_PID 2>/dev/null
}

# Catch termination signals and execute cleanup
trap cleanup EXIT

# Common setup for run_fuzzer
mkdir -p /empty-dir-for-fake-corpus-arg

# Initial sleep duration
sleep_duration=10
while true
do
  # Before sleeping, check if there are seeds in FUZZ_MERGE_FROM_RAW_DIR
  if [[ ! -z "${FUZZ_MERGE_FROM_RAW_DIR}" ]] && [[ $(ls -A "${FUZZ_MERGE_FROM_RAW_DIR}" 2>/dev/null | wc -l) -gt 0 ]]; then
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS} "Seeds found in ${FUZZ_MERGE_FROM_RAW_DIR}, skipping sleep"
  else
    # NOTE: share seed every 1.5 min
    python3 ${OTEL_LOG_SCRIPT} sleep \${sleep_duration}s
    sleep \${sleep_duration}s

    if [ \${sleep_duration} -lt 90 ]; then
      sleep_duration=\$((sleep_duration + 5))
    fi
  fi

  # Since watchdog (inotify) will not work for NFS, we just directly rsync here from remote to local multilang dir
  if [[ ! -z "${FUZZ_CRS_MULTILANG_NFS_SEED_DIR}" ]] && [[ ! -z "${FUZZ_CRS_MULTILANG_LOCAL_SEED_DIR}" ]]; then
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS} "[STEP-0] Syncing NFS seed dir (${FUZZ_CRS_MULTILANG_NFS_SEED_DIR} \$(ls ${FUZZ_CRS_MULTILANG_NFS_SEED_DIR} | wc -l) seeds) to local multilang dir (${FUZZ_CRS_MULTILANG_LOCAL_SEED_DIR})"
    mkdir -p ${FUZZ_CRS_MULTILANG_NFS_SEED_DIR}
    mkdir -p ${FUZZ_CRS_MULTILANG_LOCAL_SEED_DIR}
    rsync -a --ignore-existing ${FUZZ_CRS_MULTILANG_NFS_SEED_DIR}/ ${FUZZ_CRS_MULTILANG_LOCAL_SEED_DIR}/
  fi

  if [[ -z "${FUZZ_MERGE_FROM_TEMP_DIR}" ]]; then
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[ERR] FUZZ_MERGE_FROM_TEMP_DIR is not set, skipping seed merge"
    continue
  fi

  # Set batch parameters
  MERGE_BATCH_SIZE=3333
  MERGE_BATCH_TIMEOUT=600

  # 1. move newest seeds to temp dir for processing
  if [[ ! -z "${FUZZ_MERGE_FROM_RAW_DIR}" ]]; then
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-1] Moving at most \${MERGE_BATCH_SIZE} newest seeds from raw dir (${FUZZ_MERGE_FROM_RAW_DIR}) to temp dir (${FUZZ_MERGE_FROM_TEMP_DIR})"
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-1.0] Seeds to be discarded from ${FUZZ_MERGE_FROM_TEMP_DIR}: \$(ls "${FUZZ_MERGE_FROM_TEMP_DIR}" | wc -l) seeds"
    rm -rf "${FUZZ_MERGE_FROM_TEMP_DIR}"
    mkdir -p ${FUZZ_MERGE_FROM_TEMP_DIR}

    # Move up to MERGE_BATCH_SIZE most recent seeds (using ls -t sorts by modification time)
    # NOTE: This assumes that seeds in FUZZ_MERGE_FROM_RAW_DIR are moved in atomically
    # (not created/written in-place) to avoid race conditions during mv
    # Using ls -t to sort by time, not including hidden files
    ls -t "${FUZZ_MERGE_FROM_RAW_DIR}" | head -n \${MERGE_BATCH_SIZE} |
      xargs -I{} mv "${FUZZ_MERGE_FROM_RAW_DIR}/{}" "${FUZZ_MERGE_FROM_TEMP_DIR}/" 2>/dev/null || true
  fi

  # 2. deduplicate and merge seed (only pick fast seed)
  CURRENT_BATCH_SIZE=\$(ls -1 "${FUZZ_MERGE_FROM_TEMP_DIR}" 2>/dev/null | wc -l)
  python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-2] Merging \${CURRENT_BATCH_SIZE} seeds from temp dir to target dir"

  # Run merge
  export JAZZER_DIR="${AIXCC_JAZZER_DIR}"
  export CORPUS_DIR="/empty-dir-for-fake-corpus-arg"
  timeout -s SIGKILL \${MERGE_BATCH_TIMEOUT}s \
    stdbuf -e 0 -o 0 \
      run_fuzzer ${FUZZ_TARGET_HARNESS} \
        ${FUZZ_MERGE_OPT} \
        --agent_path=\${JAZZER_DIR}/jazzer_standalone_deploy.jar \
        -use_value_profile=1 \
        "\$@" \
        "${FUZZ_MERGE_TO_DIR}" \
        "${FUZZ_MERGE_FROM_TEMP_DIR}" \
        || echo @@@@@ exit code of Jazzer is $? @@@@@ >&2
  unset JAZZER_DIR
  unset CORPUS_DIR

  # 3. collect beepseed
  python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-3] Collecting beepseed from target dir (${FUZZ_MERGE_TO_DIR}) to beepseed dir (${BEEPSEED_DIR})"
  export ATLJAZZER_CUSTOM_SINKPOINT_CONF=${FUZZ_CUSTOM_SINK_CONF}
  export JAZZER_DIR="${ATL_JAZZER_DIR}"
  export CORPUS_DIR=${FUZZ_MERGE_TO_DIR}
  timeout -s SIGKILL \${MERGE_BATCH_TIMEOUT}s \
    stdbuf -e 0 -o 0 \
      run_fuzzer ${FUZZ_TARGET_HARNESS} \
        --agent_path=\${JAZZER_DIR}/jazzer_standalone_deploy.jar \
        ${BEEPSEED_OPTS} \
        -runs=0 \
        "\$@" \
        || echo @@@@@ exit code of Jazzer is $? @@@@@ >&2
  unset JAZZER_DIR
  unset CORPUS_DIR
  unset ATLJAZZER_CUSTOM_SINKPOINT_CONF

  # 4. produce covonly seed corpus
  python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-4] Producing covonly seed corpus from target dir (${FUZZ_MERGE_TO_DIR}) to covonly dir (${FUZZ_MERGE_TO_DIR_COVONLY})"
  export JAZZER_DIR="${AIXCC_JAZZER_DIR}"
  export CORPUS_DIR="/empty-dir-for-fake-corpus-arg"
  timeout -s SIGKILL \${MERGE_BATCH_TIMEOUT}s \
    stdbuf -e 0 -o 0 \
      run_fuzzer ${FUZZ_TARGET_HARNESS} \
        --agent_path=\${JAZZER_DIR}/jazzer_standalone_deploy.jar \
        ${FUZZ_MERGE_OPT} \
        -use_value_profile=1 \
        "\$@" \
        "${FUZZ_MERGE_TO_DIR_COVONLY}" \
        "${FUZZ_MERGE_TO_DIR}" \
        || echo @@@@@ exit code of Jazzer is $? @@@@@ >&2
  unset JAZZER_DIR
  unset CORPUS_DIR

  # 5. rsync to the crs-java seedshare dir
  if [[ ! -z "${FUZZ_CRS_JAVA_NFS_SEED_DIR}" ]]; then
    python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS}  "[STEP-5] Syncing seed from target dir (${FUZZ_MERGE_TO_DIR_COVONLY}) to crs-java seedshare dir (${FUZZ_CRS_JAVA_NFS_SEED_DIR})"
    mkdir -p ${FUZZ_CRS_JAVA_NFS_SEED_DIR}
    rsync -a --ignore-existing ${FUZZ_MERGE_TO_DIR_COVONLY}/ ${FUZZ_CRS_JAVA_NFS_SEED_DIR}/
  fi

  # summarize from how many seeds to how many seeds
  python3 ${OTEL_LOG_SCRIPT} ${FUZZ_TARGET_HARNESS} "[STEP-END] Merging seed from temp dir (\$(ls ${FUZZ_MERGE_FROM_TEMP_DIR} | wc -l) seeds) to target dir (\$(ls ${FUZZ_MERGE_TO_DIR} | wc -l) seeds, cov only \$(ls ${FUZZ_MERGE_TO_DIR_COVONLY} | wc -l) seeds)"
done
EOF
chmod +x ${WORK_DIR}/_run_fuzzer_timeout_stub.sh

timeout -s SIGKILL ${FUZZ_TTL_FUZZ_TIME}s \
  taskset -c ${FUZZ_BOUND_CPULIST} \
    stdbuf -e 0 -o 0 \
      bash ${WORK_DIR}/_run_fuzzer_timeout_stub.sh \
        --reproducer_path="${REPRODUCER_DIR}" \
        ${N_KEEP_GOING_OPT} \
        ${EXP_SEED_LEN_OPTS} \
        ${CLOSE_FD_OPT} \
        -artifact_prefix="${ARTIFACT_DIR}/" \
        -max_total_time="3600" \
        2>&1 | \
      stdbuf -e 0 -o 0 ts "%s" | \
      python3.12 -u ${SCRIPT_DIR}/jazzer_postprocessing.py -o ${RESULT_JSON} --rolling-log ${FUZZ_LOG} || true

else

if [[ -d "${FUZZ_INITIAL_CORPUS}" ]]; then
  # rsync the initial corpus to the corpus dir
  echo "FUZZ_INITIAL_CORPUS is set, rsyncing ${FUZZ_INITIAL_CORPUS} to ${CORPUS_DIR}"
  rsync -a --ignore-existing "${FUZZ_INITIAL_CORPUS}/" "${CORPUS_DIR}/"
else
  echo "FUZZ_INITIAL_CORPUS is not set, corpus dir will be empty at the beginning"
fi

#
# Kick off the fuzzer
#
cat > "${WORK_DIR}/_run_fuzzer_timeout_stub.sh" <<EOF
# Restart-on-sink-growth tunables.
# N -> M growth restarts are gated by COOLDOWN_SECONDS so each Jazzer instance
# gets at least that much productive run time before it can be killed. The
# 0 -> N case (first sinks ever arriving) bypasses the cooldown.
POLL_INTERVAL=5
GROWTH_PCT=10
COOLDOWN_SECONDS=300

# Recursively signal a process and all its descendants. We walk the tree
# ourselves instead of using process groups because run_fuzzer stays in the
# stub's process group, so the outer 'timeout -s SIGKILL' at campaign end
# continues to clean up the entire subtree in one shot.
kill_tree() {
  local pid=\$1 sig=\$2
  local c
  for c in \$(pgrep -P "\$pid" 2>/dev/null); do
    kill_tree "\$c" "\$sig"
  done
  kill -"\$sig" "\$pid" 2>/dev/null || true
}

while true
do

  export ATLJAZZER_CUSTOM_SINKPOINT_CONF=${FUZZ_CUSTOM_SINK_CONF}
  export CORPUS_DIR="${CORPUS_DIR}"
  export JAZZER_DIR="${JAZZER_DIR}"
  export ATL_OPTIONS="${BEEPSEED_OPTS} ${DIRECTED_FUZZING_ARGS} "

  if [[ -f "$RESULT_JSON" ]]; then
    FALL_THRO=\$(grep do_fall_through $RESULT_JSON | wc -l)
    if [[ \$FALL_THRO -gt 0 ]]; then
      echo "NOTE: Falling through to aixcc jazzer"
      export JAZZER_DIR="${AIXCC_JAZZER_DIR}"
      export ATL_OPTIONS=""
    fi
  fi

  # Snapshot the sink count at iteration start. One line = one sink
  # (caller#... or api#...), and sinks are monotonic, so line count is
  # a direct measure of "did the sink pool grow".
  baseline_lines=\$(wc -l < "\$ATLJAZZER_CUSTOM_SINKPOINT_CONF" 2>/dev/null || echo 0)
  iter_start_ts=\$(date +%s)
  echo "SINK_RESTART: starting run_fuzzer (baseline_lines=\$baseline_lines, growth_pct=\${GROWTH_PCT}, cooldown=\${COOLDOWN_SECONDS}s)"

  stdbuf -e 0 -o 0 \
    run_fuzzer ${FUZZ_TARGET_HARNESS} \
      --agent_path=\${JAZZER_DIR}/jazzer_standalone_deploy.jar \
      \${ATL_OPTIONS} \
      "\$@" &
  RF_PID=\$!

  # Watch for sink-conf growth while run_fuzzer runs.
  should_restart=0
  while kill -0 \$RF_PID 2>/dev/null; do
    sleep \$POLL_INTERVAL
    now=\$(date +%s)
    cur_lines=\$(wc -l < "\$ATLJAZZER_CUSTOM_SINKPOINT_CONF" 2>/dev/null || echo 0)

    # 0 -> N always triggers (first sinks ever arriving). No cooldown so
    # Jazzer stops wasting time fuzzing with an empty sink set.
    if [[ \$baseline_lines -eq 0 && \$cur_lines -gt 0 ]]; then
      echo "SINK_RESTART: 0 -> \$cur_lines, requesting restart"
      should_restart=1
      break
    fi

    # N -> M triggers when growth >= GROWTH_PCT, but only after COOLDOWN_SECONDS
    # have elapsed since this iteration started — gives each Jazzer instance a
    # minimum productive run time and prevents restart thrashing on small pools
    # or trickling sink sources.
    if [[ \$baseline_lines -gt 0 && \$((cur_lines * 100)) -ge \$((baseline_lines * (100 + GROWTH_PCT))) ]]; then
      if [[ \$((now - iter_start_ts)) -ge \$COOLDOWN_SECONDS ]]; then
        echo "SINK_RESTART: \$baseline_lines -> \$cur_lines (>= \${GROWTH_PCT}%), requesting restart"
        should_restart=1
        break
      fi
    fi
  done

  if [[ \$should_restart -eq 1 ]]; then
    # Walk run_fuzzer's descendants (/out/<harness>, atl-jazzer, java) and
    # signal each one. SIGTERM first so libfuzzer can flush corpus / jacoco /
    # result.json; SIGKILL after 15s grace.
    kill_tree \$RF_PID TERM
    for _ in {1..15}; do
      kill -0 \$RF_PID 2>/dev/null || break
      sleep 1
    done
    kill_tree \$RF_PID KILL
  fi
  wait \$RF_PID 2>/dev/null
  RF_RET=\$?
  if [[ \$RF_RET -ne 0 && \$should_restart -eq 0 ]]; then
    echo "@@@@@ exit code of Jazzer is \$RF_RET @@@@@" >&2
  fi

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
        ${N_KEEP_GOING_OPT} \
        -use_value_profile=1 \
        -rss_limit_mb=8192 \
        -artifact_prefix="${ARTIFACT_DIR}/" \
        -reload=30 \
        -max_total_time="${FUZZ_TTL_FUZZ_TIME}" \
        -dict="${DICT_FILE}" \
        ${CLOSE_FD_OPT} \
        ${EXP_SEED_LEN_OPTS} \
        ${KEEP_SEED_OPT} \
        ${COVERAGE_DUMP_OPT} 2>&1 | \
      stdbuf -e 0 -o 0 ts "%s" | \
      python3.12 -u ${SCRIPT_DIR}/jazzer_postprocessing.py -o ${RESULT_JSON} --rolling-log ${FUZZ_LOG} || true

fi
