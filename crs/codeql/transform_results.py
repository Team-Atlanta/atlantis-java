#!/usr/bin/env python3
"""
Transform CodeQL SARIF results from standard security queries to coordinate format.
"""

import json
import sys
import os
from pathlib import Path


def deduplicate_sinkpoints(coordinates):
    """Deduplicate sinkpoints, keeping only those with superset column ranges.

    If multiple sinkpoints have the same file, line, and CWE, only keep the one(s)
    whose column range is not a proper subset of any other's column range.
    """
    # Group by (file_name, line_num, cwe)
    groups = {}
    for coord in coordinates:
        key = (coord['coord']['file_name'], coord['coord']['line_num'], coord['cwe'])
        if key not in groups:
            groups[key] = []
        groups[key].append(coord)

    # For each group, keep only entries with maximal column ranges
    result = []
    for key, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Find entries whose column range is not a proper subset of any other
            for entry1 in group:
                start1 = entry1['coord']['start_column']
                end1 = entry1['coord']['end_column']

                is_maximal = True
                for entry2 in group:
                    if entry1 is entry2:
                        continue
                    start2 = entry2['coord']['start_column']
                    end2 = entry2['coord']['end_column']

                    # Check if entry1's range is a proper subset of entry2's range
                    # entry1 is a proper subset of entry2 if:
                    # - entry2's range contains entry1's range
                    # - and they're not equal
                    if start2 <= start1 and end1 <= end2 and (start2 < start1 or end2 > end1):
                        is_maximal = False
                        break

                if is_maximal:
                    result.append(entry1)

    return result


def transform_codeql_results(input_files, output_file):
    """Transform CodeQL SARIF results to coordinate format.

    Args:
        input_files: Either a single SARIF file path or a list of SARIF file paths
        output_file: Output JSON file path
    """

    # Read the SARIF file(s)
    coordinates = []

    # Handle both single file and list of files
    if isinstance(input_files, str):
        input_files = [input_files]

    for input_file in input_files:
        if not os.path.exists(input_file):
            print(f"Warning: Skipping non-existent file: {input_file}", file=sys.stderr)
            continue

        with open(input_file, 'r') as f:
            sarif_data = json.load(f)

        # Process each run in the SARIF file
        for run in sarif_data.get('runs', []):
            results = run.get('results', [])

            for result in results:
                try:
                    # Extract CWE number and message text from result
                    rule_id = result.get('ruleId', '')
                    message_text = result.get('message', {}).get('text', '')

                    # Check if the finding is filtered (message contains [FILTERED:...])
                    filtered = "[FILTERED:" in message_text

                    # Parse the class name and method name from the message. Format:
                    # "\\[class_name, method_name\\] message details... \\[FILTERED:...\\]"
                    class_name = ''
                    method_name = ''
                    if '[' in message_text and ']' in message_text:
                        first_bracket_close = message_text.index(']')
                        class_method_part = message_text[2:first_bracket_close-1]
                        if ',' in class_method_part:
                            class_name, method_name = [part.strip() for part in class_method_part.split(',', 1)]
                            message_text = message_text[first_bracket_close+1:].strip()

                    # Extract CWE number from rule ID (e.g., "java/cwe-078-command-injection" -> "CWE-078")
                    cwe_number = ''
                    if 'cwe-' in rule_id.lower():
                        parts = rule_id.lower().split('cwe-')
                        if len(parts) > 1:
                            # Extract the numeric part after 'cwe-'
                            cwe_part = parts[1].split('-')[0].split('/')[0]
                            cwe_number = f"CWE-{cwe_part}"

                    # Get all locations from the result
                    locations = result.get('locations', [])

                    for location in locations:
                        physical_location = location.get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})

                        # Extract file path
                        file_path = artifact_location.get('uri', '')
                        if not file_path:
                            continue

                        # Extract line and column information
                        start_line = region.get('startLine')
                        if start_line is None:
                            continue

                        end_line = region.get('endLine', start_line)
                        start_column = region.get('startColumn', 1)
                        end_column = region.get('endColumn', start_column)

                        # Create id: filename + start_line + start_column + end_line + end_column
                        entry_id = f"{file_path}:{start_line}:{start_column}:{end_line}:{end_column}"

                        # Check if the file is a test file (contains "Test" in the path)
                        filtered_out_test = "Test" in file_path or "/test/" in file_path.lower()

                        # Create one entry for each line from start_line to end_line
                        for line_num in range(start_line, end_line + 1):
                            coord_entry = {
                                "coord": {
                                    "line_num": line_num,
                                    "file_name": file_path,
                                    "start_column": start_column,
                                    "end_column": end_column,
                                    "class_name": class_name,
                                    "method_name": method_name
                                },
                                "id": entry_id,
                                "cwe": cwe_number,
                                "message": message_text,
                                "filtered_out_flow": filtered,
                                "filtered_out_test": filtered_out_test
                            }
                            coordinates.append(coord_entry)
                            break

                except (KeyError, ValueError) as e:
                    print(f"Warning: Skipping malformed result: {e}", file=sys.stderr)
                    continue

    # Deduplicate sinkpoints by keeping only those with superset column ranges
    unique_coordinates = deduplicate_sinkpoints(coordinates)

    # Write the transformed results
    with open(output_file, 'w') as f:
        json.dump(unique_coordinates, f, indent=2)

    print(f"Transformed {len(unique_coordinates)} unique coordinate entries from {len(input_files)} SARIF file(s) to {output_file}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 transform_results.py <input_sarif(s)> <output_json>")
        print("Example: python3 transform_results.py out.sarif transformed_results.json")
        print("Example: python3 transform_results.py file1.sarif file2.sarif ... output.json")
        sys.exit(1)

    # Last argument is output file, everything else is input
    output_file = sys.argv[-1]
    input_files = sys.argv[1:-1]

    try:
        transform_codeql_results(input_files, output_file)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
