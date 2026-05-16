#!/usr/bin/env python3
"""
Find sink points reachable from fuzzing entry points in a call graph.

This script identifies all sink points that are reachable from any fuzzing
entry point (methods named 'fuzzerTestOneInput') in the call graph.
"""

import json
import argparse
from collections import deque
from typing import Set, Dict, List


def load_json_file(filepath: str) -> dict:
    """Load and parse a JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def find_entry_points(nodes: List[dict]) -> Set[int]:
    """
    Find all fuzzing entry points in the call graph.

    Entry points are identified by method name 'fuzzerTestOneInput'.

    Args:
        nodes: List of node dictionaries from the call graph

    Returns:
        Set of node IDs that are fuzzing entry points
    """
    entry_points = set()
    for node in nodes:
        func_name = node.get('data', {}).get('func_name', '')
        if func_name == 'fuzzerTestOneInput':
            entry_points.add(node['id'])
    return entry_points


def build_call_graph(links: List[dict]) -> Dict[int, Set[int]]:
    """
    Build a call graph as an adjacency list.

    Args:
        links: List of link dictionaries with 'source' and 'target' keys

    Returns:
        Dictionary mapping source node ID to set of target node IDs
    """
    graph = {}
    for link in links:
        source = link['source']
        target = link['target']
        if source not in graph:
            graph[source] = set()
        graph[source].add(target)
    return graph


def find_reachable_nodes(entry_points: Set[int], graph: Dict[int, Set[int]]) -> Set[int]:
    """
    Find all nodes reachable from any entry point using BFS.

    Args:
        entry_points: Set of entry point node IDs
        graph: Call graph as adjacency list

    Returns:
        Set of all reachable node IDs (including entry points)
    """
    reachable = set()
    queue = deque(entry_points)
    reachable.update(entry_points)

    while queue:
        current = queue.popleft()

        # Get all targets called by current node
        targets = graph.get(current, set())
        for target in targets:
            if target not in reachable:
                reachable.add(target)
                queue.append(target)

    return reachable


def create_node_index(nodes: List[dict]) -> Dict[int, dict]:
    """
    Create an index mapping node IDs to node data.

    Args:
        nodes: List of node dictionaries

    Returns:
        Dictionary mapping node ID to node data
    """
    return {node['id']: node for node in nodes}


def match_sink_to_node(sink: dict, nodes: List[dict]) -> int:
    """
    Match a sink point to a node in the call graph.

    Args:
        sink: Sink dictionary with coord information
        nodes: List of node dictionaries from call graph

    Returns:
        Node ID if match found, None otherwise
    """
    sink_file = sink['coord']['file_name']
    sink_line = sink['coord']['line_num']

    for node in nodes:
        node_data = node.get('data', {})
        node_file = node_data.get('file_name', '')
        start_line = node_data.get('start_line', -1)
        end_line = node_data.get('end_line', -1)

        # Handle path prefix differences between call graph and sink files
        # CG may have "repo/" or "oss-fuzz/projects/aixcc/jvm/<project>/" prefixes
        node_file_normalized = node_file
        if node_file.startswith('repo/'):
            node_file_normalized = node_file[5:]  # Remove "repo/"
        elif 'oss-fuzz/projects/aixcc/jvm/' in node_file:
            # Remove prefix up to and including the project directory
            parts = node_file.split('oss-fuzz/projects/aixcc/jvm/', 1)
            if len(parts) > 1:
                # Also skip the project name directory
                remaining = parts[1].split('/', 1)
                if len(remaining) > 1:
                    node_file_normalized = remaining[1]

        # Match if normalized paths match and line is within range
        if node_file_normalized == sink_file and start_line <= sink_line <= end_line:
            return node['id']

    return None


def main():
    parser = argparse.ArgumentParser(
        description='Find sink points reachable from fuzzing entry points'
    )
    parser.add_argument(
        'sinks_file',
        help='Path to JSON file containing sink points (e.g., geonetwork.json)'
    )
    parser.add_argument(
        'callgraph_file',
        help='Path to JSON file containing call graph (e.g., joern-cg.json)'
    )
    parser.add_argument(
        '--output',
        '-o',
        help='Output file for reachable sinks (default: stdout)'
    )
    parser.add_argument(
        '--in-place',
        '-i',
        action='store_true',
        help='Modify the sinks file in-place instead of creating a new file'
    )
    parser.add_argument(
        '--include-filtered',
        action='store_true',
        help='Include sinks that were filtered out'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Print verbose information'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.in_place and args.output:
        parser.error("Cannot use both --in-place and --output")

    # Load input files
    if args.verbose:
        print(f"Loading sinks from {args.sinks_file}...")
    sinks = load_json_file(args.sinks_file)

    if args.verbose:
        print(f"Loading call graph from {args.callgraph_file}...")
    callgraph = load_json_file(args.callgraph_file)

    nodes = callgraph['nodes']
    links = callgraph['links']

    # Find entry points
    if args.verbose:
        print("Finding fuzzing entry points...")
    entry_points = find_entry_points(nodes)

    if args.verbose:
        print(f"Found {len(entry_points)} entry point(s)")
        node_index = create_node_index(nodes)
        for ep_id in entry_points:
            ep_data = node_index[ep_id]['data']
            print(f"  - {ep_data.get('class_name', '')}.{ep_data.get('func_name', '')} "
                  f"at {ep_data.get('file_name', '')}:{ep_data.get('start_line', '')}")

    if not entry_points:
        print("WARNING: No fuzzing entry points found!")
        if args.output:
            with open(args.output, 'w') as f:
                json.dump([], f, indent=2)
        else:
            print("[]")
        return

    # Build call graph
    if args.verbose:
        print("Building call graph...")
    graph = build_call_graph(links)

    # Find reachable nodes
    if args.verbose:
        print("Finding reachable nodes...")
    reachable = find_reachable_nodes(entry_points, graph)

    if args.verbose:
        print(f"Found {len(reachable)} reachable node(s)")

    # Match sinks to nodes and add reachability information
    if args.verbose:
        print("Matching sinks to reachable nodes...")

    reachable_count = 0
    unmatched_count = 0
    output_sinks = []

    for sink in sinks:
        # Skip filtered sinks unless requested
        if not args.include_filtered:
            if sink.get('filtered_out_flow', False) or sink.get('filtered_out_test', False):
                continue

        # Create a copy of the sink to add reachability info
        sink_with_reachability = sink.copy()

        node_id = match_sink_to_node(sink, nodes)

        if node_id is not None:
            if node_id in reachable:
                sink_with_reachability['reachable'] = True
                reachable_count += 1
            else:
                sink_with_reachability['reachable'] = False
        else:
            # Sink not matched to any node in call graph
            sink_with_reachability['reachable'] = False
            unmatched_count += 1

        output_sinks.append(sink_with_reachability)

    # Output results
    print(f"\nResults:")
    print(f"  Total sinks processed: {len(output_sinks)}")
    print(f"  Reachable sinks: {reachable_count}")
    print(f"  Unreachable sinks: {len(output_sinks) - reachable_count}")
    print(f"  Unmatched sinks (not in CG): {unmatched_count}")

    # Determine output file
    if args.in_place:
        output_file = args.sinks_file
    elif args.output:
        output_file = args.output
    else:
        output_file = None

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output_sinks, f, indent=2)
        print(f"\nSinks with reachability info written to {output_file}")
    else:
        # Print human-readable summary to stdout
        print(f"\nReachable sinks:")
        for sink in output_sinks:
            if sink.get('reachable', False):
                print(f"  [{sink.get('cwe', 'N/A')}] {sink['coord']['file_name']}:{sink['coord']['line_num']}")

        print(f"\nUnreachable sinks:")
        for sink in output_sinks:
            if not sink.get('reachable', False):
                print(f"  [{sink.get('cwe', 'N/A')}] {sink['coord']['file_name']}:{sink['coord']['line_num']}")


if __name__ == '__main__':
    main()
