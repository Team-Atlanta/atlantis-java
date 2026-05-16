#!/bin/bash
set -x
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Usage: ./run.sh <database_path> <json_output_path> [threads]
# Environment: CODEQL_CWES - required, comma-separated CWE IDs (e.g. "CWE-078,CWE-089").

DATABASE_PATH="$1"
JSON_OUTPUT="$2"
THREADS="${3:-4}"

if [ -z "$CODEQL_CWES" ]; then
    echo "ERROR: CODEQL_CWES is not set"
    exit 1
fi

SARIF_DIR="${JSON_OUTPUT%.json}_sarifs"
mkdir -p "$SARIF_DIR"
cd "$SCRIPT_DIR"

# Explicit CWE → query file mapping. Only CWEs listed here can be run.
declare -A CWE_QUERIES=(
    [CWE-022]="sink-queries/queries/CWE-022-path-traversal.ql"
    [CWE-078]="sink-queries/queries/CWE-078-command-injection.ql"
    [CWE-089]="sink-queries/queries/CWE-089-sql-injection.ql"
    [CWE-090]="sink-queries/queries/CWE-090-ldap-injection.ql"
    [CWE-094]="sink-queries/queries/CWE-094-script-injection.ql"
    [CWE-117]="sink-queries/queries/CWE-117-log-injection.ql"
    [CWE-470]="sink-queries/queries/CWE-470-unsafe-reflection.ql"
    [CWE-502]="sink-queries/queries/CWE-502-unsafe-deserialization.ql"
    [CWE-611]="sink-queries/queries/CWE-611-xxe.ql"
    [CWE-643]="sink-queries/queries/CWE-643-xpath-injection.ql"
    [CWE-730]="sink-queries/queries/CWE-730-regex-injection.ql"
    [CWE-918]="sink-queries/queries/CWE-918-ssrf.ql"
)

# Resolve requested CWEs via the mapping.
queries=()
IFS=',' read -ra selected <<< "$CODEQL_CWES"
for cwe in "${selected[@]}"; do
    ql="${CWE_QUERIES[$cwe]}"
    if [ -z "$ql" ]; then
        echo "ERROR: Unknown CWE: $cwe"
        exit 1
    fi
    queries+=("$ql")
done

if [ ${#queries[@]} -eq 0 ]; then
    echo "ERROR: No queries found for CODEQL_CWES=$CODEQL_CWES"
    exit 1
fi

echo "Running ${#queries[@]} CodeQL queries on $DATABASE_PATH (threads=$THREADS)"

codeql database analyze "$DATABASE_PATH" \
    --format=sarifv2.1.0 \
    --output="$SARIF_DIR/results.sarif" \
    --threads="$THREADS" \
    --rerun \
    "${queries[@]}"

# Transform SARIF to coordinate JSON
python3 transform_results.py "$SARIF_DIR"/*.sarif "$JSON_OUTPUT"
