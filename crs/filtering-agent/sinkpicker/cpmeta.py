#!/usr/bin/env python3

import json
import logging
from pathlib import Path
from typing import Any, Dict

from .utils import CRS_ERR_LOG, CRS_WARN_LOG

logger = logging.getLogger(__name__)


CRS_ERR = CRS_ERR_LOG("cpmeta")
CRS_WARN = CRS_WARN_LOG("cpmeta")


class CPMetadata:
    """Class for handling CP metadata from a JSON file."""

    def __init__(self, json_file: str):
        """Initialize with the path to the metadata JSON file."""
        self.json_file = Path(json_file)
        self.metadata: Dict[str, Any] = self._load_metadata()

    def _load_metadata(self) -> Dict[str, Any]:
        """Load and validate the metadata JSON file."""
        if not self.json_file.exists():
            raise FileNotFoundError(f"Metadata file not found: {self.json_file}")

        try:
            with open(self.json_file) as f:
                metadata = json.load(f)

            if not isinstance(metadata, dict):
                raise ValueError("Metadata must be a JSON object")

            return metadata
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in metadata file: {e}")

    def get_cp_name(self) -> str:
        """Get the CP name from the metadata."""
        return self.metadata["cp_name"]

    def get_target_class(self, target_harness: str) -> str | None:
        """Get the target class for the harness."""
        for info in self.metadata.get("harnesses", {}).values():
            if info.get("name") == target_harness:
                return info.get("target_class")

    def get_classpath(self, target_harness: str) -> str | None:
        """Get the classpath for the harness."""
        for info in self.metadata.get("harnesses", {}).values():
            if info.get("name") == target_harness:
                return ":".join(info.get("classpath", []))

    def get_custom_sink_conf_path(self) -> Path | None:
        """Get the path to the custom sink configuration file."""
        path = self.metadata.get("custom_sink_conf_path", None)
        return Path(path) if path else None

    def resolve_file_path(self, class_name: str, file_name: str):
        if "." in class_name:
            # fully qualified class_name -> pkg_name
            # com.example.foo.Bar -> com.example.foo
            pkg_name = ".".join(class_name.split(".")[:-1])
            pkg_path_part = pkg_name.replace(".", "/")
        else:
            return None

        pkg_file_paths = [
            Path(f) for f in self.metadata.get("pkg2files", {}).get(pkg_name, [])
        ]
        matching_files = [
            f for f in pkg_file_paths if f.name == file_name and pkg_path_part in str(f)
        ]
        # Multiple matches? Warn and use the longest one
        if len(matching_files) > 1:
            logger.warning(
                f"{CRS_WARN} Multiple file matches for {class_name}.{file_name}: {matching_files}"
            )
            return str(max(matching_files, key=lambda p: len(str(p))))
        elif len(matching_files) == 1:
            return str(matching_files[0])
        else:
            return None

    def resolve_frame_to_file_path(self, frame) -> str | None:
        if not frame or "class_name" not in frame or "file_name" not in frame:
            return None
        return self.resolve_file_path(frame["class_name"], frame["file_name"])

    def get_proj_path(self) -> Path | None:
        """Get the OSS-Fuzz project directory path from metadata.

        Returns:
            Path to the OSS-Fuzz project directory (harnesses, build scripts, etc.)
        """
        proj_path = self.metadata.get("proj_path", None)
        return Path(proj_path) if proj_path else None

    def get_repo_src_path(self) -> Path | None:
        """Get the challenge project source code directory path from metadata.

        Returns:
            Path to the challenge project source code directory
        """
        repo_src_path = self.metadata.get("repo_src_path", None)
        return Path(repo_src_path) if repo_src_path else None
