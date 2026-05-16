# CodeQL Sink Analysis Tool

Runs a curated set of CWE-specific CodeQL queries against a Java database and
emits a coordinate-format JSON list of sink locations suitable for downstream
consumption by the CRS sink pipeline.

## Setup

```bash
./init.sh
```

This installs Python dependencies and fetches the CodeQL packs declared in
`sink-queries/qlpack.yml` (notably `codeql/java-all`) into the local CodeQL
package cache. Requires `codeql` in `PATH` and Python 3.

## Usage

```bash
CODEQL_CWES=CWE-078,CWE-089 ./run.sh <database_path> <output_json_path> [threads]
```

**Parameters:**
- `database_path` — CodeQL database to analyze (must be finalized)
- `output_json_path` — where the coordinate-format JSON will be written
- `threads` — optional, passed to `codeql database analyze` (default: 4)

**Environment:**
- `CODEQL_CWES` — required, comma-separated subset of supported CWEs to run.
  The script hardcodes an explicit CWE → query file mapping; unknown CWEs
  are rejected.

### What `run.sh` does

1. Validates `CODEQL_CWES` and resolves each CWE to its `.ql` file.
2. Runs `codeql database analyze` against the database with the selected
   queries, writing per-query SARIF to a `_sarifs` directory adjacent to the
   output path.
3. Transforms all SARIF files into a single coordinate-format JSON via
   `transform_results.py`.

### Reachability filter

After `run.sh`, `find_reachable_sinks.py` can annotate each sink with a
`reachable` flag by cross-referencing a call graph. The sinkdetection module
runs this automatically with `--output <separate_file>` so the raw CodeQL
results are preserved.

## Output format

Each entry in the output JSON looks like:

```json
{
  "coord": {
    "line_num": 342,
    "method_name": "tokenizeRow",
    "file_name": "BasicCParser.java",
    "class_name": "org/apache/commons/imaging/common/BasicCParser",
    ...
  },
  "cwe": "CWE-730",
  "filtered_out_flow": false,
  "filtered_out_test": false
}
```

## Layout

```
├── init.sh                   # Installs deps and the CodeQL pack
├── run.sh                    # Runs the selected CWE queries
├── transform_results.py      # SARIF -> coordinate JSON
├── find_reachable_sinks.py   # Annotates sinks with call-graph reachability
├── requirements.txt          # Python deps for init.sh
└── sink-queries/             # QL pack
    ├── qlpack.yml            # Declares codeql/java-all dependency
    └── queries/
        ├── CWE-022-path-traversal.ql
        ├── CWE-078-command-injection.ql
        ├── CWE-089-sql-injection.ql
        ├── CWE-090-ldap-injection.ql
        ├── CWE-094-script-injection.ql
        ├── CWE-117-log-injection.ql
        ├── CWE-470-unsafe-reflection.ql
        ├── CWE-502-unsafe-deserialization.ql
        ├── CWE-611-xxe.ql
        ├── CWE-643-xpath-injection.ql
        ├── CWE-730-regex-injection.ql
        └── CWE-918-ssrf.ql
```
