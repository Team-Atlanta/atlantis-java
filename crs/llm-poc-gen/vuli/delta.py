import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from functools import reduce
from pathlib import Path
from typing import Optional

import aiofiles
import chardet
from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from unidiff import Hunk, PatchedFile, PatchSet

from vuli.blackboard import Blackboard
from vuli.common.decorators import SEVERITY, async_safe, step
from vuli.common.singleton import Singleton
from vuli.cp import CP
from vuli.joern import Joern
from vuli.model_manager import ModelManager
from vuli.pathfinder import PathFinder
from vuli.sink import Origin, SinkManager, SinkProperty
from vuli.struct import LLMParseException, LLMRetriable, VulInfo


class DeltaHandler(ABC):
    def __init__(self):
        self._logger = logging.getLogger("DeltaHandler")

    @abstractmethod
    async def handle(self, patched_files: list[PatchedFile]) -> None:
        pass


class SinkManagerDeltaHandler(DeltaHandler):
    def __init__(self):
        self._logger = logging.getLogger("SinkManagerDeltaHandler")

    @async_safe(None, SEVERITY.ERROR, "SinkManagerDeltaHandler")
    async def handle(self, patched_files: list[PatchedFile]) -> None:
        added_lines: dict[str, list[tuple[int, int]]] = self._get_added_lines(
            patched_files
        )
        if len(added_lines) == 0:
            self._logger.info("Not Found Added Lines")
            return

        self._logger.debug(
            f"""[Added Lines]
{"\n".join([f"{file_path}: {", ".join(f"({start_idx}~{end_idx})" for start_idx, end_idx in added_lines[file_path])}" for file_path in added_lines])}
"""
        )
        sinks: set[int] = await self._find_sinks_from_sink_manager(added_lines)
        self._logger.info(f"Found Sinks: {len(sinks)}")
        await self._mark_sinks_from_delta(sinks)

    def _get_added_lines(
        self, patched_files: list[PatchedFile]
    ) -> dict[str, list[tuple[int, int]]]:
        return {
            str(Path(patched_file.target_file[2:])): self._get_added_lines_per_file(
                patched_file
            )
            for patched_file in patched_files
        }

    def _get_added_lines_per_file(
        self, patched_file: PatchedFile
    ) -> list[tuple[int, int]]:
        return reduce(
            lambda y, x: y + self._get_added_lines_per_hunk(x), patched_file, []
        )

    def _get_added_lines_per_hunk(self, hunk: Hunk) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        base_idx: int = hunk.target_start
        start_idx: Optional[int] = None
        for idx, line in enumerate(hunk):
            if line.is_added and start_idx is None:
                start_idx = idx
                continue
            if not line.is_added and start_idx is not None:
                result.append((start_idx + base_idx, idx - 1 + base_idx))
                start_idx = None
        if start_idx is not None:
            result.append((start_idx + base_idx, idx + base_idx))
        return result

    async def _find_sinks_from_sink_manager(
        self, added_lines: dict[str, list[tuple[int, int]]]
    ) -> set[int]:
        sinks: dict[int, SinkProperty] = await SinkManager().get()
        sink_ids: list[int] = list(sinks.keys())
        query: str = f"""
cpg.ids({",".join([str(sink_id) for sink_id in sink_ids])})
    .collect{{case x: CfgNode => x}}
    .where(_.or({",".join([f"""
        _.and(
            _.method.filename(".*{file_path}$"),
            _.or({",".join([f"""
                _.and(_.lineNumberGte({start_inx}), _.lineNumberLte({end_idx}))""" for start_inx, end_idx in added_lines[file_path]])}
            )
        )""" for file_path in added_lines])})
    ).map(_.id).l"""
        joern_result: list[int] = await Joern().run_query(query)
        return set(joern_result)

    async def _mark_sinks_from_delta(self, sinks: set[int]) -> None:
        await SinkManager().add_batch(
            {
                x: SinkProperty(bug_types=set(), origins=set({Origin.FROM_DELTA}))
                for x in sinks
            }
        )


class DeltaParser:
    def __init__(self):
        self._logger = logging.getLogger("DeltaParser")

    async def parse(self, text: str) -> dict:
        jsons = [x for x in re.findall(r"```json\n(.*?)```", text, re.DOTALL)]
        if len(jsons) == 0:
            self._logger.debug(f"LLM Answer: {text}")
            raise LLMParseException(
                "No json included. Please include ```json\n``` for answer"
            )
        if len(jsons) > 1:
            self._logger.debug(f"LLM Answer: {text}")
            raise LLMParseException(
                "More than one json included. PLease include only one json for answer"
            )

        try:
            root: dict = json.loads(jsons[0])
        except json.JSONDecodeError as e:
            self._logger.debug(f"LLM Answer: {jsons[0]}")
            raise LLMParseException(
                f"Invalid json format. Please answer json again. Below is an error message while parsing the json.\n{e}"
            )

        if not isinstance(root, list):
            self._logger.debug(f"Json: {root}")
            raise LLMParseException(
                "Invalid json format. Root element must be list. Please answer json again."
            )

        necessary_keys: set[str] = set(
            {"hunk_number", "line_number_in_hunk", "vulnerability_type"}
        )
        for object in root:
            missing_keys: set[str] = necessary_keys - set(object.keys())
            if len(missing_keys) > 0:
                raise LLMParseException(
                    f"Missing keys ({",".join(missing_keys)}) in this object {object}. Please answer json again."
                )
        return root


class LLMDeltaHandler(DeltaHandler):
    def __init__(self, threashold: int = -1):
        self._logger = logging.getLogger("LLMDeltaHandler")
        self._limit: int = 100000
        self._threashold: int = threashold

    @async_safe(None, SEVERITY.ERROR, "LLMDeltaHandler")
    async def handle(self, patched_files: list[PatchedFile]) -> None:
        if not self._condition(patched_files):
            return
        await self._run(patched_files)

    def _condition(self, patched_files: list[PatchedFile]) -> bool:
        """
        Handler will work if the below condition is satisfied
        - there is any reachable harnesses written in blackboard
        - threashold is -1, otherwise the number of total characters are
          under the threashold.
        """
        if len(Blackboard().diff_harnesses) == 0:
            self._logger.info("LLM will not analyze diff [reason=No reachable harness]")
            return False

        if (
            self._threashold != -1
            and self._total_text_len(patched_files) > self._threashold
        ):
            self._logger.info(
                f"LLM will not analyze diff [reason=Exceeds threshold, threshold={self._threashold}]"
            )
            return False
        return True

    def _total_text_len(self, patched_files: list[PatchedFile]) -> int:
        return reduce(
            lambda y, x: y + len(x),
            [
                str(line)
                for patched_file in patched_files
                for hunk in patched_file
                for line in hunk
            ],
            0,
        )

    async def _run(self, patched_files: list[PatchedFile]) -> None:
        self._logger.info(f"Target Files: {len(patched_files)}")
        hunks: list[tuple[PatchedFile, Hunk]] = self._create_hunk_list(patched_files)
        self._logger.info(f"Target Hunks: {len(hunks)}")
        hunk_messages: list[str] = self._create_hunk_messages(hunks)
        inferred_sinks: list[dict] = await self._infer_sinks(hunk_messages)
        self._logger.info(f"Inferred sinks: {len(inferred_sinks)}")
        sinks: list[dict] = self._create_outputs(inferred_sinks, hunks)
        await self._update_sink_manager(sinks)

    def _create_hunk_list(
        self, patched_files: list[PatchedFile]
    ) -> list[tuple[PatchedFile, Hunk]]:
        hunks: list[tuple[PatchedFile, Hunk]] = []
        for patched_file in patched_files:
            if (
                not patched_file.target_file.endswith(".java")
                and not patched_file.target_file.endswith(".kt")
                or "/src/test" in patched_file.target_file
            ):
                self._logger.info(f"Skip: {patched_file.target_file}")
                continue

            for hunk in patched_file:
                hunks.append((patched_file, hunk))
        return hunks

    def _create_hunk_messages(self, hunks: list[tuple[PatchedFile, Hunk]]) -> list[str]:
        hunk_msgs: list[str] = []
        for idx, hunk in enumerate(hunks):
            if len(str(hunk[1])) > self._limit:
                self._logger.info(f"Skip Hunk (Size exceeded):\n{hunk[1]}")
                continue

            lines: list[str] = str(hunk[1]).split("\n")
            line_number_width: int = len(str(len(lines)))
            lines: list[str] = [
                f"{str(index + 1).rjust(line_number_width)}   {line}"
                for index, line in enumerate(lines)
            ]
            hunk_msgs.append(f"Hunk #{idx}\n{"\n".join(lines)}")
        return hunk_msgs

    async def _infer_sinks(self, hunk_messages: list[str]) -> list[dict]:
        async def _infer(msg: str) -> list[dict]:
            messages: list[BaseMessage] = [
                HumanMessage(
                    content=f"""
Find any problematic code that can cause endless run in the given diff file.
Please answer is as below format.
Line number should indicate the line in hunk where vulnerability will be triggered.
```json
[
{{"hunk_number": xx, "line_number_in_hunk": yy, "vulnerability_type": "", "related_code": "xxx"}},
...
]
```
<DIFF>
{msg}"""
                )
            ]
            for i in range(0, 3):
                try:
                    return await ModelManager().invoke_atomic(
                        messages, "gpt-4.1", DeltaParser(), agent="delta"
                    )
                except LLMRetriable:
                    await asyncio.sleep(60)
                except Exception:
                    return []

        diff: str = ""
        result: list[dict] = []
        total_word_size: int = reduce(lambda y, x: y + len(x), hunk_messages, 0)
        word_count: int = 0
        for hunk_message in hunk_messages:
            if len(diff) == 0:
                diff += hunk_message
                word_count += len(hunk_message)
                continue

            if len(diff) + len(hunk_message) + 2 > self._limit:
                result.extend(await _infer(diff))
                self._logger.info(f"Procssed: {word_count} / {total_word_size}")
                diff = ""

            diff += f"\n\n{hunk_message}"
            word_count += len(hunk_message)
        if len(diff) > 0:
            result.extend(await _infer(diff))
            self._logger.info(f"Procssed: {word_count} / {total_word_size}")
        return result

    def _create_outputs(
        self, inferred_sinks: list[dict], hunks: list[tuple[PatchedFile, Hunk]]
    ) -> list[dict]:
        result: list[dict] = []
        for data in inferred_sinks:
            output: dict = self._create_output(hunks, data)
            if output.keys() == 0:
                self._logger.warning(f"Invalid Format: Skipped ({data})")
                continue
            result.append(output)
        return result

    @step({}, SEVERITY.WARNING, "LLMDeltaHandler")
    def _create_output(self, hunks: list[tuple[PatchedFile, Hunk]], src: dict) -> dict:
        necessary_keys: set[str] = set(
            {"hunk_number", "line_number_in_hunk", "vulnerability_type"}
        )
        if len(necessary_keys - set(src.keys())) > 0:
            return {}

        hunk_number: int = src["hunk_number"]
        hunk_line_number: int = src["line_number_in_hunk"]
        vulnerability_type: str = src["vulnerability_type"]
        file_path: str = hunks[hunk_number][0].target_file
        file_path: str = file_path[file_path.find("/") + 1 :]
        return {
            "file_path": file_path,
            "line": self._create_code_line(hunks[hunk_number][1], hunk_line_number),
            "v_type": vulnerability_type,
        }

    def _create_code_line(self, hunk: Hunk, hunk_line: int) -> int:
        result: int = hunk.target_start - 1
        for line in str(hunk).split("\n")[1:hunk_line]:
            if line.startswith("-"):
                continue
            result += 1
        return result

    async def _update_sink_manager(self, sinks: list[dict]) -> None:
        if len(sinks) == 0:
            return
        query: list[str] = [
            f'("{sink["file_path"]}", {sink["line"]}, "{sink["v_type"]}")'
            for sink in sinks
        ]
        query: str = f"""
List({",".join(query)})
    .map(x => (cpg.call.where(_.method.filename(".*" + x._1)).where(_.lineNumber(x._2)).headOption, x._3))
    .collect{{case (Some(a), b) => Map("id" -> a.id, "v_type" -> b)}}"""
        result: list[dict] = await Joern().run_query(query)
        self._logger.info(f"Found {len(result)} Nodes in Joern")
        self._logger.debug(result)
        sinks_to_add: dict[int, SinkProperty] = {
            x["id"]: SinkProperty(
                bug_types=set({"sink-Timeout"}), origins=set({Origin.FROM_DELTA})
            )
            for x in result
        }
        await SinkManager().add_batch(sinks_to_add)


class DeltaReachableAnalyzer(DeltaHandler):

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)

    async def handle(self, patched_files: list[PatchedFile]) -> None:
        self._logger.info("Start")

        methods: list[dict] = await self._collect_methods(patched_files)
        self._logger.info(f"Identified methods: {len(methods)}")
        if len(methods) == 0:
            return
        self._logger.info(
            f"Added/Modified Methods by diff\n{"\n".join([f"- {method["name"]}:{method["line"]}" for method in methods])}"
        )
        Blackboard()._modified_methods |= set({method["name"] for method in methods})

        harnesses: set[str] = CP().get_harnesses()
        paths: list[VulInfo] = [
            path
            for harness in harnesses
            for path in await self._find_path(harness, {int(x["id"]) for x in methods})
        ]
        if len(paths) == 0:
            self._logger.info(f"Reachable Harnesses to diff: {len(paths)}")
            return

        for path in paths:
            msg: str = f"Harness: {path.harness_id}\n"
            for idx, v_path in enumerate(path.v_paths):
                msg += f"- Path {idx}: {v_path.path}:{v_path.line}({v_path.method})\n"
            self._logger.info(f"Call flows to Diff:\n{msg}")

        await Blackboard().add_diff_harnesses({str(x.harness_id) for x in paths})

    @async_safe([], SEVERITY.WARNING, "DeltaReachableAnalyzer")
    async def _find_path(self, harness: str, methods: set[int]) -> list[VulInfo]:
        return await PathFinder()._cg(harness, methods)

    @async_safe(set(), SEVERITY.WARNING, "DeltaReachableAnalyzer")
    async def _collect_methods(self, diffs: list[PatchedFile]) -> list[dict]:
        table: dict[str, list[tuple[int, int]]] = {
            file.path: self.__collect_methods_per_file(file) for file in diffs
        }
        query: str = f"""
cpg.method.where(_.or(
    {",".join([f"_.and(_.filename(\".*{path}\"), _.or({",".join([f"_.and(_.lineNumberLte({end}), _.lineNumberEndGte({start}))" for start, end in ranges])}))" for path, ranges in table.items()])}
)).map(x => Map("id" -> x.id, "name" -> x.fullName, "line" -> x.lineNumber.getOrElse(-1))).l
"""
        method: list[dict] = await Joern().run_query(query)
        return method

    @step([], SEVERITY.WARNING, "DeltaReachableAnalyzer")
    def __collect_methods_per_file(self, diff: PatchedFile) -> list[tuple[int, int]]:
        return reduce(lambda y, x: y + self.__collect_line_ranges(x), diff, [])

    @step([], SEVERITY.WARNING, "DeltaReachableAnalyzer")
    def __collect_line_ranges(self, hunk: Hunk) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        add_start_idx: Optional[int] = None
        del_start_idx: Optional[int] = None
        prev_line: int = hunk.target_start
        for line in hunk:
            if line.is_added and add_start_idx is None:
                add_start_idx = line.target_line_no
            else:
                if not line.is_added and add_start_idx is not None:
                    result.append((add_start_idx, prev_line))
                    add_start_idx = None
                if line.is_removed and del_start_idx is None:
                    del_start_idx = prev_line
            prev_line = line.target_line_no

        if add_start_idx is not None:
            result.append((add_start_idx, prev_line))

        if len(result) > 0:
            return result
        if del_start_idx is None:
            return []
        result.append((del_start_idx, del_start_idx))
        return result


class DeltaManager(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("DeltaManager")
        self._handlers: list[DeltaHandler] = []

    def add(self, *args) -> None:
        for arg in args:
            if not isinstance(arg, DeltaHandler):
                self._logger.warning(
                    f"Skip to add handler: Invalid type(type={arg.__class__.__name__})"
                )
                continue
            self._handlers.append(arg)

    def clear(self) -> None:
        self._handlers = []

    async def handle(self) -> None:
        if len(self._handlers) == 0:
            self._logger.info("No handlers")
            return

        patched_files: list[PatchedFile] = await self._get_patched_file()
        if len(patched_files) == 0:
            self._logger.info(
                "Delta Analyzer Will Not Work [reason=No Patched File Found]"
            )
            return
        [await self._handle(handler, patched_files) for handler in self._handlers]
        await Blackboard().save()

    @async_safe(None, SEVERITY.ERROR, "DeltaManager")
    async def _handle(
        self, handler: DeltaHandler, patched_files: list[PatchedFile]
    ) -> None:
        await handler.handle(patched_files)

    @async_safe([], SEVERITY.ERROR, "DeltaManager")
    async def _get_patched_file(self) -> list[PatchedFile]:
        @step("utf-8", SEVERITY.WARNING, "DeltaManager")
        def infer_format(src: bytes) -> str:
            result: dict = chardet.detect(raw)
            if result is None or "encoding" not in result or result["encoding"] is None:
                return "utf-8"
            return result["encoding"]

        diff_path: Optional[Path] = CP()._diff_path
        if diff_path is None:
            self._logger.info("Diff File Not Found")
            return []
        self._logger.info(f"Diff File Found [path={diff_path}]")

        async with aiofiles.open(diff_path, mode="rb") as f:
            raw: bytes = await f.read()
            encoding: str = infer_format(raw)
            enc: str = raw.decode(encoding, errors="ignore")
            patch = PatchSet.from_string(enc)
        self._logger.info("Diff File Loaded")

        result: list[PatchedFile] = []
        for file in patch:
            if (
                not file.target_file.endswith(".java")
                and not file.target_file.endswith(".kt")
                or "/src/test" in file.target_file
            ):
                self._logger.info(f"Skip: {file.target_file}")
                continue

            result.append(file)
        return result
