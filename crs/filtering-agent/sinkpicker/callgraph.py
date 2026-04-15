#!/usr/bin/env python3

import logging
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)


class CallGraph:
    """Call graph representation for finding paths between methods."""

    def __init__(self, graph_data: dict):
        """
        Initialize call graph from Joern JSON format.

        Args:
            graph_data: Dict with 'nodes' and 'links' keys
        """
        self.nodes_by_id = {}
        self.adjacency = {}  # node_id -> list of target node_ids

        # Index nodes by ID
        for node in graph_data.get("nodes", []):
            node_id = node["id"]
            self.nodes_by_id[node_id] = node["data"]
            self.adjacency[node_id] = []

        # Build adjacency list
        for link in graph_data.get("links", []):
            source = link["source"]
            target = link["target"]
            if source in self.adjacency:
                self.adjacency[source].append(target)

        logger.info(f"CallGraph initialized with {len(self.nodes_by_id)} nodes")

    def find_node_by_method(self, class_name: str, func_name: str) -> Optional[int]:
        """
        Find a node by class name and function name.

        Args:
            class_name: Fully qualified class name
            func_name: Function/method name

        Returns:
            Node ID if found, None otherwise
        """
        for node_id, data in self.nodes_by_id.items():
            if data.get("class_name").endswith("." + class_name) and data.get("func_name") == func_name:
                return node_id
        return None

    def find_node_by_location(self, file_name: str, line_num: int) -> Optional[int]:
        """
        Find a node that contains the given file and line number.

        Args:
            file_name: File path (may be partial)
            line_num: Line number

        Returns:
            Node ID if found, None otherwise
        """
        # Normalize file_name for comparison
        normalized_file = file_name.replace("\\", "/")

        for node_id, data in self.nodes_by_id.items():
            node_file = data.get("file_name", "").replace("\\", "/")

            # Check if file names match (handle partial paths)
            if not (normalized_file in node_file or node_file in normalized_file):
                continue

            # Check if line number is within method bounds
            start_line = data.get("start_line")
            end_line = data.get("end_line")

            if start_line is not None and end_line is not None:
                if start_line <= line_num <= end_line:
                    return node_id

        return None

    def find_path_bfs(self, start_node_id: int, end_node_id: int, max_depth: int = 20) -> Optional[list[int]]:
        """
        Find a path from start_node to end_node using BFS.

        Args:
            start_node_id: Starting node ID
            end_node_id: Target node ID
            max_depth: Maximum search depth

        Returns:
            List of node IDs forming the path, or None if no path found
        """
        if start_node_id not in self.nodes_by_id or end_node_id not in self.nodes_by_id:
            return None

        if start_node_id == end_node_id:
            return [start_node_id]

        # BFS with path tracking
        queue = deque([(start_node_id, [start_node_id])])
        visited = {start_node_id}

        while queue:
            current_id, path = queue.popleft()

            # Check depth limit
            if len(path) > max_depth:
                continue

            # Explore neighbors
            for neighbor_id in self.adjacency.get(current_id, []):
                if neighbor_id == end_node_id:
                    return path + [neighbor_id]

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return None

    def format_path(self, path: list[int]) -> str:
        """
        Format a path as a human-readable string.

        Args:
            path: List of node IDs

        Returns:
            Formatted call path string
        """
        if not path:
            return "(no path found)"

        lines = []
        for i, node_id in enumerate(path):
            data = self.nodes_by_id.get(node_id, {})
            class_name = data.get("class_name", "?")
            func_name = data.get("func_name", "?")
            file_name = data.get("file_name", "?")
            start_line = data.get("start_line", "?")

            # Format: [1] ClassName.methodName() at file.java:line
            lines.append(f"  [{i+1}] {class_name}.{func_name}()")
            lines.append(f"      at {file_name}:{start_line}")

        return "\n".join(lines)

    def get_node_info(self, node_id: int) -> dict:
        """Get node data by ID."""
        return self.nodes_by_id.get(node_id, {})
