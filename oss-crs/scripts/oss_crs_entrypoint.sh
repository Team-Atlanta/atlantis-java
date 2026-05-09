#!/bin/bash
# oss-crs entrypoint: bridges the framework environment to run-crs-java.sh
set -e

#############################################
# 1. Download build outputs from framework
#############################################
libCRS download-build-output build /out
libCRS download-build-output crs/proj /out/crs/proj
libCRS download-build-output crs/src /out/crs/src

#############################################
# 2. Register output directories
#    Framework watches these and collects artifacts
#############################################
mkdir -p /artifacts/povs /artifacts/corpus
libCRS register-submit-dir pov /artifacts/povs
libCRS register-submit-dir seed /artifacts/corpus

#############################################
# 3. Bridge environment variables
#    Framework injects OSS_CRS_* vars,
#    run-crs-java.sh expects different names
#############################################
# 2.5. Start local Redis for expkit caching
redis-server --daemonize yes --loglevel warning
export CPMETA_REDIS_URL="redis://localhost:6379"

export CRS_TARGET="${OSS_CRS_TARGET}"
export LITELLM_URL="${OSS_CRS_LLM_API_URL}"
if [ -n "$OSS_CRS_LLM_API_KEY_FILE" ] && [ -f "$OSS_CRS_LLM_API_KEY_FILE" ]; then
    OSS_CRS_LLM_API_KEY="$(cat "$OSS_CRS_LLM_API_KEY_FILE")"
    export OSS_CRS_LLM_API_KEY
fi
export LITELLM_KEY="${OSS_CRS_LLM_API_KEY}"
export AIXCC_LITELLM_HOSTNAME="${OSS_CRS_LLM_API_URL}"

#############################################
# 4. Run the original CRS entry point
#    Pass target harness as $1
#############################################
exec ${JAVA_CRS_SRC}/run-crs-java.sh "${OSS_CRS_TARGET_HARNESS}"
