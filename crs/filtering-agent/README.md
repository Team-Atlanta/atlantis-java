# Sink Picker

An AI-powered tool that analyzes potential vulnerability sink points in Java code and selects the most promising ones for further analysis.

## Overview

The Sink Picker uses an LLM-powered agent to evaluate vulnerability sink locations identified by static analysis tools. It analyzes the code context, data flow, and exploitability factors to select the most promising sink point in each file.

## Installation

```bash
pip3 install -r requirements.txt
pip3 install -e .
```

## Environment Setup

Set the required environment variables:

```bash
export LITELLM_KEY=your_api_key_here
export AIXCC_LITELLM_HOSTNAME=your_litellm_endpoint
```

## Usage

```bash
python -m sinkpicker.pick_sinks \
    /path/to/input_sinks.json \
    /path/to/output_sinks.json \
    --metadata /path/to/cpmetadata.json \
    --harness-cwe-pairs "harness1:CWE-022,harness2:CWE-089,harness3:CWE-022" \
    --call-graph /path/to/call-graph.json \
    --workdir /path/to/working/directory \
    --verbose
```

### Arguments

- `input`: Path to input JSON file with sink candidates (required)
- `output`: Path to save output JSON file with filtering decisions (required)
- `--metadata`: Path to CP metadata JSON file (required)
- `--harness-cwe-pairs`: Comma-separated list of harness:CWE pairs, e.g., "harness1:CWE-022,harness2:CWE-089". Each pair is analyzed independently. (required)
- `--call-graph`: Path to call graph JSON file in Joern format (required)
- `--workdir`: Working directory for agent artifacts (optional)
- `--gen-model`: LLM model used by the filtering agent (default: gpt-5)
- `--max-iterations`: Maximum agent iterations (default: 15)
- `--temperature`: LLM temperature (default: 0.0)
- `--max-workers`: Maximum parallel workers for processing files (default: 10)
- `--verbose`: Enable verbose logging

### Advanced Options

```bash
# Pick a different model
--gen-model claude-3-7-sonnet-20250219

# Adjust agent behavior
--max-iterations 20
--temperature 0.1

# Control parallel processing (useful for managing API rate limits)
--max-workers 5
```

## Input Format

JSON array of sink candidates with harness information:
```json
[
  {
    "coord": {
      "line_num": 840,
      "file_name": "src/main/java/Example.java",
      "start_column": 30,
      "end_column": 43
    },
    "id": "src/main/java/Example.java:840:30:840:43",
    "harness": "harness1",
    "cwe": "CWE-022",
    "message": "Path traversal sink",
    "filtered_out_flow": false,
    "filtered_out_test": false,
    "reachable": true
  }
]
```

## Output Format

Same format as input, with additional `unexploitable` and `in_final_result` fields:
- `unexploitable`: List of harness names where the sink is NOT exploitable (well-protected)
- `in_final_result`: List of harness names where the sink should be included in the final result set

```json
[
  {
    "coord": {
      "line_num": 840,
      "file_name": "src/main/java/Example.java",
      "start_column": 30,
      "end_column": 43
    },
    "id": "src/main/java/Example.java:840:30:840:43",
    "harness": "harness1",
    "cwe": "CWE-022",
    "message": "Path traversal sink",
    "filtered_out_flow": false,
    "filtered_out_test": false,
    "reachable": true,
    "unexploitable": ["harness2"],
    "in_final_result": ["harness1", "harness3"]
  }
]
```

**Notes**:
- `unexploitable`: List of harnesses for which the agent determined the sink is unexploitable. Only added to sinks that were analyzed by the agent.
- `in_final_result`: List of harnesses for which the sink should be in the final result
  - Includes harnesses where no agent analysis was performed
  - Includes harnesses where the sink is potentially exploitable
  - Includes harnesses where analysis failed (conservative approach)
  - Excludes harnesses where agent determined sink is unexploitable
- Since analysis is per-harness, the same sink may be unexploitable for one harness but exploitable for another

## How It Works

1. **Input Processing**: Loads sink candidates and filters by harness and CWE for each pair
2. **Harness File Loading**: Searches for and reads the harness file (e.g., `JenkinsOne.java`) from the oss-fuzz directory
3. **Call Path Discovery**: Uses call graph to find path from `fuzzerTestOneInput` to sink location
4. **Parallel Analysis**: Processes multiple sinks concurrently (up to 10 by default) using a **two-stage LangGraph workflow**:

   **Stage 1 - Research Phase:**
   - Agent receives initial prompt with:
     - Harness file contents (e.g., `JenkinsOne.java`)
     - Call path from `fuzzerTestOneInput` to the sink
   - Agent explores code using tools (read_file, list_directory, search_files)
   - Gathers information about data flow, input validation, and accessibility
   - Call path helps trace how user input flows through the execution to reach the sink
   - Runs for up to max_iterations (default: 15)

   **Stage 2 - Selection Phase:**
   - Takes research findings and initial prompt as input
   - Uses structured LLM output to make final decision
   - Returns SinkSelection with chosen sink ID and reasoning
   - Guarantees a decision (either a sink ID or 'none')

4. **Output Generation**: Updates all sinks with `filtered_out_agent` field

## Supported CWEs

- CWE-022: Path Traversal
- CWE-078: OS Command Injection
- CWE-089: SQL Injection
- CWE-090: LDAP Injection
- CWE-094: Code Injection (Bean Validation & Script Injection)
- CWE-117: Log Injection
- CWE-470: Unsafe Reflection
- CWE-502: Deserialization of Untrusted Data
- CWE-611: XXE (XML External Entity)
- CWE-643: XPath Injection
- CWE-730: Regex Injection / ReDoS
- CWE-918: Server-Side Request Forgery (SSRF)

## Architecture

The tool consists of three main components:

1. **pick_sinks.py**: Main orchestration logic with parallel processing
2. **picker_agent.py**: Two-stage LangGraph agent
   - Research phase: ReAct agent with exploration tools
   - Selection phase: Structured LLM output (Pydantic models)
   - State graph manages flow between phases
3. **picker_prompt.py**: CWE-specific prompt generation with code context
