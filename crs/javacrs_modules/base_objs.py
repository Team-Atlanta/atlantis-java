#!/usr/bin/env python3
import copy
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from uuid import UUID

import aiofiles
from pydantic import BaseModel


class File(BaseModel):
    name: str
    path: Path

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "File":
        return cls(name=data["name"], path=Path(data["path"]))

    def to_dict(self):
        return {"name": self.name, "path": str(self.path)}


class Function(BaseModel):
    func_name: str
    file_name: str | None  # absolute path
    class_name: str | None = None
    func_sig: str | None = None
    method_desc: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "Function":
        return cls(**data)

    def to_dict(self):
        return {
            "func_name": self.func_name,
            "file_name": self.file_name,
            "class_name": self.class_name,
            "func_sig": self.func_sig,
            "method_desc": self.method_desc,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


class CodeLocation(BaseModel):
    file: File
    function: Function | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "CodeLocation":
        file = File.frm_dict(data["file"])
        function = Function.frm_dict(data["function"]) if data.get("function") else None
        return cls(
            file=file,
            function=function,
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            start_column=data.get("start_column"),
            end_column=data.get("end_column"),
        )

    def to_dict(self):
        return {
            "file": self.file.to_dict(),
            "function": self.function.to_dict() if self.function else None,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
        }


class ConfidenceLevel(Enum):
    HIGH = "high"
    LOW = "low"


class SarifReachabilityResult(BaseModel):
    code_location: CodeLocation
    confidence_level: ConfidenceLevel
    callgraph: dict  # jsonable python dict of CallGraph. See sarif.validator.reachability.callgraph.CallGraph.to_json()


class SarifAnalysisResult(BaseModel):
    sarif_id: UUID
    rule_id: str
    reachable_harness: str
    reachability_results: list[SarifReachabilityResult]


class CRSJAVASarifReport:
    sarif_id: UUID
    rule_id: str
    reachable_harnesses: Set[str]
    code_locations: Set[CodeLocation]
    solved: bool

    def __init__(
        self,
        sarif_id: UUID,
        rule_id: str,
        reachable_harnesses: Set[str],
        code_locations: Set[CodeLocation],
        solved: bool,
    ):
        self.sarif_id = sarif_id
        self.rule_id = rule_id
        self.reachable_harnesses = reachable_harnesses
        self.code_locations = code_locations
        self.solved = solved

    def add_result(self, result: SarifAnalysisResult) -> bool:
        """Add a result to the report."""
        updated = False
        assert result.sarif_id == self.sarif_id
        assert result.rule_id == self.rule_id
        if result.reachable_harness not in self.reachable_harnesses:
            self.reachable_harnesses.add(result.reachable_harness)
            updated = True
        for r in result.reachability_results:
            if r.code_location not in self.code_locations:
                self.code_locations.add(r.code_location)
                updated = True
        return updated

    def merge(self, other: "CRSJAVASarifReport") -> bool:
        """Merge another CRSJAVASarifReport into this one."""
        if self.sarif_id != other.sarif_id or self.rule_id != other.rule_id:
            return False
        updated = False
        for h in other.reachable_harnesses:
            if h not in self.reachable_harnesses:
                self.reachable_harnesses.add(h)
                updated = True
        for loc in other.code_locations:
            if loc not in self.code_locations:
                self.code_locations.add(loc)
                updated = True
        if other.solved and not self.solved:
            self.solved = True
            updated = True
        return updated

    def is_solved(self) -> bool:
        """Check if the report is solved."""
        return self.solved

    def mark_as_solved(self):
        """Mark the report as solved."""
        self.solved = True

    @classmethod
    def frm_results(
        cls, results: List[SarifAnalysisResult], solved: bool
    ) -> "CRSJAVASarifReport":
        if len(results) == 0:
            raise ValueError("Cannot create CRSJAVASarifReport from empty results")
        # check sarif_id and rule_id consistency
        for result in results:
            if (
                result.sarif_id != results[0].sarif_id
                or result.rule_id != results[0].rule_id
            ):
                raise ValueError("All results must have the same sarif_id and rule_id")
        obj = cls(
            sarif_id=results[0].sarif_id,
            rule_id=results[0].rule_id,
            reachable_harnesses=set(),
            code_locations=set(),
            solved=solved,
        )
        for result in results:
            obj.add_result(result)
        return obj

    @classmethod
    def frm_dict(cls, data) -> "CRSJAVASarifReport":
        sarif_id = UUID(data["sarif_id"])
        rule_id = data["rule_id"]
        reachable_harnesses = set(data.get("reachable_harnesses", []))
        code_locations = {
            CodeLocation.frm_dict(cl) for cl in data.get("code_locations", [])
        }
        solved = data["solved"]
        return cls(
            sarif_id=sarif_id,
            rule_id=rule_id,
            reachable_harnesses=reachable_harnesses,
            code_locations=code_locations,
            solved=solved,
        )

    def to_dict(self):
        sorted_harnesses = list(self.reachable_harnesses)
        sorted_harnesses.sort()
        sorted_locs = list(self.code_locations)
        sorted_locs.sort(
            key=lambda loc: (
                loc.file.name,
                loc.function.func_name,
                loc.start_line,
                loc.end_line,
                loc.start_column,
                loc.end_column,
            )
        )
        return {
            "sarif_id": str(self.sarif_id),
            "rule_id": self.rule_id,
            "reachable_harnesses": sorted_harnesses,
            "code_locations": [cl.to_dict() for cl in sorted_locs],
            "solved": self.solved,
        }


class InsnCoordinate:
    """Unique coorindate of an insn in bytecode."""

    def __init__(
        self,
        class_name: str,
        method_name: str,
        method_desc: str,
        bytecode_offset: int,
        mark_desc: str,
        file_name: str,
        line_num: int,
    ):
        self.class_name = class_name
        self.method_name = method_name
        self.method_desc = method_desc
        self.bytecode_offset = bytecode_offset
        self.mark_desc = mark_desc
        self.file_name = file_name
        self.line_num = line_num

        self.has_src_info = self.mark_desc and self.class_name and self.line_num != -1
        self.has_bytecode_info = (
            self.mark_desc
            and self.class_name
            and self.method_name
            and self.method_desc
            and self.bytecode_offset != -1
        )
        if not self.has_src_info and not self.has_bytecode_info:
            raise ValueError(
                f"Incomplete info in InsnCoordinate: src_info {self.has_src_info}, bytecode_info {self.has_bytecode_info}, {self.__dict__}"
            )
        if self.class_name is not None:
            self.class_name = self.class_name.replace("/", ".")

    @classmethod
    def frm_dict(cls, coord_dict: Dict[str, Any]) -> "InsnCoordinate":
        return cls(
            class_name=coord_dict.get("class_name", None),
            method_name=coord_dict.get("method_name", None),
            method_desc=coord_dict.get("method_desc", None),
            bytecode_offset=int(v) if (v := coord_dict.get("bytecode_offset")) is not None else -1,
            mark_desc=coord_dict.get("mark_desc", None),
            file_name=coord_dict.get("file_name", None),
            line_num=int(v) if (v := coord_dict.get("line_num")) is not None else -1,
        )

    def to_conf(self) -> str | None:
        """Convert the InsnCoordinate to a conf."""
        if self.has_bytecode_info:
            return "#".join(
                [
                    "caller",
                    self.class_name.replace(".", "/"),
                    self.method_name,
                    self.method_desc if self.method_desc else "",
                    self.file_name if self.file_name else "",
                    str(self.line_num),
                    str(self.bytecode_offset),
                    self.mark_desc if self.mark_desc else "",
                ]
            )
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name,
            "method_name": self.method_name,
            "method_desc": self.method_desc,
            "bytecode_offset": self.bytecode_offset,
            "mark_desc": self.mark_desc,
            "file_name": self.file_name,
            "line_num": self.line_num,
        }

    def _is_in_stack_frame(self, frame: str) -> bool:
        return (f"{self.class_name}.{self.method_name}") in frame and (
            f"({self.file_name}:{self.line_num})"
        ) in frame

    def is_in_stack_frames(self, frames: list[str]) -> bool:
        for frame in frames:
            if self._is_in_stack_frame(frame):
                return True
        return False

    def redis_key(self) -> str:
        """Get a Redis key for the InsnCoordinate."""
        return f"coord#{self.class_name}#{self.method_name}#{self.method_desc}#{self.bytecode_offset}#{self.file_name}#{self.line_num}#{self.mark_desc}"

    def id(self) -> str:
        """Get a unique ID for the InsnCoordinate."""
        return f"{self.class_name}.{self.method_name}.{self.method_desc}.{self.bytecode_offset}.{self.file_name}.{self.line_num}.{self.mark_desc}"

    def __hash__(self):
        return hash(self.id())

    def __eq__(self, other: Any):
        if not isinstance(other, InsnCoordinate):
            return False
        return self.id() == other.id()

    def __str__(self):
        return f"coord @ <{self.class_name} {self.method_name} {self.method_desc} {self.bytecode_offset} {self.file_name} {self.line_num} {self.mark_desc}>"

    def __repr__(self):
        return (
            f"InsnCoordinate(class_name='{self.class_name}', "
            f"method_name='{self.method_name}', "
            f"method_desc='{self.method_desc}', "
            f"bytecode_offset={self.bytecode_offset}, "
            f"mark_desc='{self.mark_desc}', "
            f"file_name='{self.file_name}', "
            f"line_num={self.line_num})"
        )


class BeepSeed:
    """beepseed is an input reaching a marked code point."""

    def __init__(
        self,
        target_cp: str,
        target_harness: str,
        data_sha1: str,
        data_hex_str: str | None,
        data_len: int,
        coord: InsnCoordinate,
        stack_hash: str,
        stack_trace: list | None,
        json_obj: Dict[str, Any],
    ):
        self.target_cp = target_cp
        self.target_harness = target_harness
        self.data_sha1 = data_sha1
        self.data_hex_str = data_hex_str
        self.data_len = data_len
        self.coord = coord
        # NOTE: stack_hash is about beepseed exec stacks
        self.stack_hash = stack_hash
        self.stack_trace = stack_trace
        self.json_obj = json_obj

    @classmethod
    def frm_dict(cls, dict_obj: Dict[str, Any]) -> "BeepSeed":
        """Create a BeepSeed object from a dictionary."""
        return cls(
            target_cp=dict_obj["target_cp"],
            target_harness=dict_obj["target_harness"],
            data_sha1=dict_obj["data_sha1"],
            data_hex_str=dict_obj.get("data", None),
            data_len=dict_obj["data_len"],
            coord=InsnCoordinate.frm_dict(dict_obj["coordinate"]),
            stack_hash=dict_obj["stack_hash"],
            stack_trace=dict_obj.get("stack_trace", None),
            json_obj=dict_obj,
        )

    @classmethod
    async def frm_beep_file(cls, json_path: Path) -> "BeepSeed":
        """Create a BeepSeed object from a JSON file path."""
        async with aiofiles.open(json_path, mode="r") as f:
            json_obj = json.loads(await f.read())

        json_obj["data_len"] = len(json_obj["data"]) // 2 if "data" in json_obj else 0
        return cls.frm_dict(json_obj)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the BeepSeed object to a JSON-serializable dictionary."""
        return {
            "target_cp": self.target_cp,
            "target_harness": self.target_harness,
            "data_sha1": self.data_sha1,
            "data": self.data_hex_str,
            "data_len": self.data_len,
            "coordinate": self.coord.to_dict(),
            "stack_hash": self.stack_hash,
            "stack_trace": self.stack_trace,
        }

    def is_empty_data(self) -> bool:
        return self.data_len == 0

    def filter_frames_from_codemarker(self, stack_frames=None):
        """Filter strategy: Remove frames starting from codemarker report function."""
        if stack_frames is None:
            stack_frames = self.stack_trace

        if not stack_frames:
            return []

        filtered_frames = []
        for frame in stack_frames[::-1]:
            frame_str = frame.get("frame_str", "")

            # Stop when we find the codemarker instrumentation frame
            if (
                "com.code_intelligence.jazzer.api.Jazzer.reportCodeMarkerHit(Jazzer.java:229)"
                in frame_str
            ):
                break

            filtered_frames.append(frame_str)
        filtered_frames.reverse()
        return filtered_frames

    def get_bytes(self) -> bytes:
        """Get the data bytes from the hex string."""
        if self.data_hex_str:
            return bytes.fromhex(self.data_hex_str)
        return b""

    def redis_key(self) -> str:
        """Get a unique ID for the BeepSeed."""
        return f"beep#{self.data_sha1}#{self.coord.redis_key()}"

    def id(self) -> str:
        """Get a unique ID for the BeepSeed."""
        return f"{self.coord.id()}.{self.data_sha1}"

    def __hash__(self):
        return hash(self.id())

    def __eq__(self, other):
        if not isinstance(other, BeepSeed):
            return False
        return self.id() == other.id()

    def __str__(self):
        return f"beep <{self.coord}, {self.stack_hash}, {self.data_sha1}, {self.data_len} bytes>"

    def __repr__(self):
        return (
            f"BeepSeed(target_cp='{self.target_cp}', "
            f"target_harness='{self.target_harness}', "
            f"data_sha1='{self.data_sha1}', "
            f"data_hex_str={self.data_hex_str}, "
            f"data_len={self.data_len}, "
            f"coord={self.coord}, "
            f"stack_hash='{self.stack_hash}', "
            f"stack_trace={self.stack_trace})"
        )


class Crash:
    """Represents a crash report."""

    def __init__(
        self,
        harness_name: str,
        coord: InsnCoordinate,
        sanitizer: str,
        crash_msg: str,
        frames: List[str],
        dedup_token: str,
        artifact_name: str,
        artifact_path: str,
    ):
        self.harness_name = harness_name
        self.coord = coord
        self.sanitizer = sanitizer
        self.crash_msg = crash_msg
        self.frames = frames
        self.dedup_token = dedup_token
        self.artifact_name = artifact_name
        self.artifact_path = artifact_path
        self.artifact_hexstr = Path(artifact_path).read_bytes().hex()

    def __hash__(self):
        return hash(
            (
                self.harness_name,
                self.coord,
                self.sanitizer,
                self.dedup_token,
                self.artifact_hexstr,
            )
        )

    def __eq__(self, other):
        try:
            return (
                self.harness_name == other.harness_name
                and self.coord == other.coord
                and self.sanitizer == other.sanitizer
                and self.dedup_token == other.dedup_token
                and self.artifact_hexstr == other.artifact_hexstr
            )
        except AttributeError:
            return False


class Sinkpoint:
    """Represents a sink point in the Java code where vulnerabilities might be exploited."""

    def __init__(
        self,
        coord: InsnCoordinate,
        type: Set[str],
        in_diff: bool,
        sarif_reports: Set[CRSJAVASarifReport] = None,
        beepseeds: Set[BeepSeed] = None,
        crashes: Set[Any] = None,
        ana_reachability: Dict[str, bool] = None,
        ana_exploitability: Dict[str, bool] = None,
    ):
        self.coord = coord
        self.type: Set[str] = set(type)
        self.in_diff = in_diff
        self.sarif_reports: Dict[UUID, CRSJAVASarifReport] = {
            report.sarif_id: report for report in sarif_reports or {}
        }
        self.beepseeds: Set[BeepSeed] = set(beepseeds or set())
        self.crashes: Set[Any] = set(crashes or set())
        self.ana_reachability = dict(ana_reachability or dict())
        self.ana_exploitability = dict(ana_exploitability or dict())
        # asserts
        for t in self.type:
            assert isinstance(t, str), f"Invalid type in Sinkpoint: {t}"
        for k, v in self.ana_reachability.items():
            assert isinstance(k, str), f"Invalid type in Sinkpoint: {t}"
            assert isinstance(v, bool), f"Invalid type in Sinkpoint: {v}"
        for k, v in self.ana_exploitability.items():
            assert isinstance(k, str), f"Invalid type in Sinkpoint: {t}"
            assert isinstance(v, bool), f"Invalid type in Sinkpoint: {v}"

    def data_n_hash(self) -> Tuple[str, str]:
        """Generate a hash based only on content values for cross-process comparisons."""
        content = json.dumps(self.to_dict(), sort_keys=True)
        return content, hashlib.md5(content.encode()).hexdigest()

    @classmethod
    def frm_dict(cls, sink_dict: Dict[str, Any]) -> "Sinkpoint":
        """Create a sinkpoint from a dictionary."""
        coord_dict = sink_dict.get("coord", {})
        if len(coord_dict) == 0:
            # NOTE: Try use sink_dict directly if no coord key is provided
            # This is for llmpocgen & static-analysis results
            coord_dict = sink_dict
        sarif_reports = {
            CRSJAVASarifReport.frm_dict(report)
            for report in sink_dict.get("sarif_reports") or []
        }
        beepseeds = {
            BeepSeed.frm_dict(beepseed) for beepseed in sink_dict.get("beepseeds") or []
        }
        type = set(sink_dict.get("type") or set())
        mark_desc = coord_dict.get("mark_desc", None)
        if mark_desc:
            type.add(mark_desc)
        return cls(
            coord=InsnCoordinate.frm_dict(coord_dict),
            type=type,
            in_diff=sink_dict.get("in_diff", False),
            sarif_reports=sarif_reports,
            beepseeds=beepseeds,
            crashes=None,
            ana_reachability=sink_dict.get("ana_reachability", None),
            ana_exploitability=sink_dict.get("ana_exploitability", None),
        )

    @classmethod
    def frm_beepseed(cls, beepseed: BeepSeed) -> "Sinkpoint":
        """Create a sinkpoint based on the beepseed."""
        return cls(
            coord=beepseed.coord,
            type={beepseed.coord.mark_desc},
            in_diff=False,
            sarif_reports=set(),
            beepseeds={beepseed},
            crashes=set(),
            ana_reachability=None,
            ana_exploitability=None,
        )

    @classmethod
    def frm_crash(cls, crash: Crash) -> "Sinkpoint":
        """Create a sinkpoint based on the crash."""
        return cls(
            coord=crash.coord,
            type={crash.coord.mark_desc},
            in_diff=False,
            sarif_reports=set(),
            beepseeds=set(),
            crashes={crash},
            ana_reachability=None,
            ana_exploitability=None,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the sinkpoint to a JSON-serializable dictionary."""
        sorted_types = list(self.type)
        sorted_types.sort()
        sorted_sarif_ids = list(self.sarif_reports.keys())
        sorted_sarif_ids.sort()
        sorted_beepseeds = list(self.beepseeds)
        sorted_beepseeds.sort(key=lambda b: b.data_sha1)
        return {
            "coord": self.coord.to_dict(),
            "type": sorted_types,
            "in_diff": self.in_diff,
            "sarif_reports": [
                self.sarif_reports[sarif_id].to_dict() for sarif_id in sorted_sarif_ids
            ],
            "beepseeds": [beepseed.to_dict() for beepseed in sorted_beepseeds],
            "ana_reachability": dict(self.ana_reachability),
            "ana_exploitability": dict(self.ana_exploitability),
            "reached": self.reached(),
            "exploited": self.exploited(),
        }

    def mark_as_sarif_target_if_should(
        self, logger, report: CRSJAVASarifReport
    ) -> bool:
        """Check and mark the sinkpoint as a SARIF target if should."""
        marked_locs = (
            self.sarif_reports[report.sarif_id].code_locations
            if report.sarif_id in self.sarif_reports
            else set()
        )
        marked = False
        for loc in report.code_locations:
            if loc in marked_locs:
                marked = True
                break
            if (
                loc.function is None
                or loc.function.class_name is None
                or loc.start_line is None
            ):
                logger(
                    f"Invalid code location {loc.function} {loc.start_line} {loc.end_line} in SARIF result {report.sarif_id} {report.rule_id} {report.reachable_harnesses}, skipping"
                )
                continue
            if self.coord.line_num == -1:
                continue
            if loc.function.class_name != self.coord.class_name:
                # NOTE: we assume sarif report always use . in class_name
                continue
            # Same class, now check if fall in line num scope
            start_line = loc.start_line
            end_line = loc.end_line if loc.end_line else loc.start_line
            if start_line <= self.coord.line_num <= end_line:
                marked = True
                break
        if marked:
            if report.sarif_id not in self.sarif_reports:
                self.sarif_reports[report.sarif_id] = report
            else:
                self.sarif_reports[report.sarif_id].merge(report)
            for h in report.reachable_harnesses:
                self.ana_reachability[h] = True
        return marked

    def merge(self, sp: "Sinkpoint") -> bool:
        """Update the sinkpoint with another sinkpoint's info, True => merge succ."""
        updated = False
        if self.coord != sp.coord:
            return updated
        for t in sp.type:
            if t not in self.type:
                self.type.add(t)
                updated = True
        if not self.in_diff and sp.in_diff:
            self.in_diff = True
            updated = True
        for sarif_id, report in sp.sarif_reports.items():
            if sarif_id not in self.sarif_reports:
                self.sarif_reports[sarif_id] = report
                updated = True
            else:
                updated |= self.sarif_reports[sarif_id].merge(report)
        for beepseed in sp.beepseeds:
            if beepseed not in self.beepseeds:
                self.beepseeds.add(beepseed)
                updated = True
        for crash in sp.crashes:
            if crash not in self.crashes:
                self.crashes.add(crash)
                updated = True
        for h, rslt in sp.ana_reachability.items():
            if h not in self.ana_reachability:
                self.ana_reachability[h] = rslt
                updated = True
            elif self.ana_reachability[h] != rslt:
                # NOTE: we directly remove the conflict
                del self.ana_reachability[h]
                updated = True
        for h, rslt in sp.ana_exploitability.items():
            if h not in self.ana_exploitability:
                self.ana_exploitability[h] = rslt
                updated = True
            elif self.ana_exploitability[h] != rslt:
                # NOTE: we directly remove the conflict
                del self.ana_exploitability[h]
                updated = True
        return updated

    def redis_key(self) -> str:
        """Get a Redis key for the Sinkpoint."""
        return f"sink#{self.coord.redis_key()}"

    def is_in_stack_frames(self, frames: List[str]) -> bool:
        """Check if this sinkpoint appears in the given stack frames."""
        return self.coord.is_in_stack_frames(frames)

    def exploited(self) -> bool:
        """Return True if the sinkpoint has been exploited (has crashes)."""
        return len(self.crashes) > 0

    def reached(self) -> bool:
        """Return True if the sinkpoint has been reached (has beepseeds)."""
        # In case the beepseed update is delayed
        return len(self.beepseeds) > 0 or len(self.crashes) > 0

    def in_prio(self) -> bool:
        """Check if the sinkpoint is in priority (in_diff/sarif & not exploited)."""
        return len(self.crashes) == 0 and (self.in_diff or len(self.sarif_reports) > 0)

    def __str__(self) -> str:
        """String representation of the sinkpoint."""
        return f"sink @ <{self.coord}, type:{self.type} {self.in_diff}, beepseeds: {len(self.beepseeds)}, sarif_reports: {len(self.sarif_reports)}, reached: {self.reached()}, exploited: {self.exploited()}>"

    def __repr__(self) -> str:
        """Detailed string representation of the sinkpoint."""
        return (
            f"Sinkpoint(coord={self.coord}, "
            f"type='{self.type}', "
            f"reached={self.reached()}, "
            f"exploited={self.exploited()})"
        )


class CallGraphSource:
    """Represents a call graph source."""

    def __init__(self, tool: str, version: str):
        self.tool = tool
        self.version = version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
        }

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "CallGraphSource":
        return cls(
            tool=data["tool"],
            version=data["version"],
        )

    def __hash__(self):
        return hash((self.tool, self.version))


class HarnessDiffReachability:
    """Represents diff analysis result of one harness."""

    def __init__(
        self, harness_name: str, reachable: bool, cg_source: set[CallGraphSource]
    ):
        self.harness_name = harness_name
        self.reachable = reachable
        self.cg_source = cg_source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "harness_name": self.harness_name,
            "reachable": self.reachable,
            "cg_source": [source.to_dict() for source in self.cg_source],
        }

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "HarnessDiffReachability":
        cg_source = [CallGraphSource.frm_dict(source) for source in data["cg_source"]]
        return cls(
            harness_name=data["harness_name"],
            reachable=data["reachable"],
            cg_source=cg_source,
        )

    def merge(self, diff: "HarnessDiffReachability") -> bool:
        """Merge another HarnessDiffReachability into this one."""
        if self.harness_name != diff.harness_name:
            return False
        self.reachable = self.reachable or diff.reachable
        self.cg_source.update(diff.cg_source)
        return True


class DiffReachabilityReport:
    """Represents a diff analysis result."""

    def __init__(self, h_reach_list: List[HarnessDiffReachability] = None):
        self.h_reach_list = copy.deepcopy(h_reach_list) if h_reach_list else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            h_reach.harness_name: h_reach.to_dict() for h_reach in self.h_reach_list
        }

    def to_json(self) -> str:
        """Convert the DiffReachabilityReport to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def get_reachable_harnesses(self) -> List[str]:
        """Get the list of reachable harnesses."""
        return [
            h_reach.harness_name for h_reach in self.h_reach_list if h_reach.reachable
        ]

    def from_all_cg_sources(self) -> bool:
        """Check if all call graph sources are the same."""
        has_joern, has_soot, has_sarif = False, False, False
        for h_reach in self.h_reach_list:
            if h_reach.cg_source.tool == "joern":
                has_joern = True
            elif h_reach.cg_source.tool == "soot":
                has_soot = True
            elif h_reach.cg_source.tool == "sarif":
                has_sarif = True
        return has_joern and has_soot and has_sarif

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "DiffReachabilityReport":
        h_reach_list = [HarnessDiffReachability.frm_dict(h) for h in data.values()]
        return cls(h_reach_list=h_reach_list)

    @classmethod
    def frm_llmpocgen(cls, blackboard: Dict[str, Any]) -> "DiffReachabilityReport":
        cg_sources = []
        joern_cg_src = blackboard["merged_joern_cg"]
        soot_cg_src = blackboard["merged_soot_cg"]
        sarif_cg_src = blackboard["merged_sarif_cg"]
        if joern_cg_src != "":
            cg_sources.append(CallGraphSource(tool="joern", version=joern_cg_src))
        if soot_cg_src != "":
            cg_sources.append(CallGraphSource(tool="soot", version=soot_cg_src))
        if sarif_cg_src != "":
            cg_sources.append(CallGraphSource(tool="sarif", version=sarif_cg_src))

        h_reach_list = [
            HarnessDiffReachability(
                harness_name=harness,
                reachable=True,
                cg_source=cg_sources,
            )
            for harness in blackboard["diff"]["harnesses"]
        ]
        return cls(h_reach_list=h_reach_list)

    def merge(self, diff: "DiffReachabilityReport"):
        """Merge another DiffReachability into this one."""
        for new_h in diff.h_reach_list:
            for old_h in self.h_reach_list:
                if old_h.harness_name == new_h.harness_name:
                    old_h.merge(new_h)
                    break
            else:
                self.h_reach_list.append(new_h)
