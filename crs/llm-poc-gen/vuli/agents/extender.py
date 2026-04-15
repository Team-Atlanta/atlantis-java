import asyncio
import copy
import logging
import random
import sys
from collections import defaultdict
from typing import Optional, TypedDict

from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.messages.system import SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledGraph

from vuli.agents.common import check_state
from vuli.agents.parser import JsonParser
from vuli.common.decorators import SEVERITY, async_safe
from vuli.cp import CP
from vuli.joern import Joern
from vuli.model_manager import ModelManager
from vuli.struct import CodeLocation, LLMRetriable


class Extender:
    class State(TypedDict):
        code_table: dict[str, list[tuple[int, int]]]
        cost: float
        end: CodeLocation
        saved_cost: float
        start: CodeLocation
        targets: list[str]
        point: str
        llm_result: dict[str, list[tuple[int, int]]]
        new_code_table: dict[str, list[tuple[int, int]]]
        models: list[str]
        harness_id: str

    def __init__(self, reader):
        self._logger = logging.getLogger("extender")
        self.__reader = reader

    def compile(self) -> CompiledGraph:
        graph = StateGraph(Extender.State)
        graph.add_node("init", self.init)
        graph.add_node("llm", self.llm)
        graph.add_node("extend_method", self.extend_method)
        graph.add_node("extend_member", self.extend_member)
        graph.add_edge(START, "init")
        graph.add_edge("init", "llm")
        graph.add_edge("llm", "extend_method")
        graph.add_edge("extend_method", "extend_member")
        graph.add_edge("extend_member", END)
        return graph.compile()

    def init(self, state: dict) -> dict:
        check_state(state, {"code_table"})
        state["cost"] = 0.0
        state["new_code_table"] = copy.deepcopy(state["code_table"])
        state["saved_cost"] = 0.0

        if len(state.get("models", [])) == 0:
            state["models"] = ModelManager().get_all_model_names()
        else:
            state["models"] = [
                x for x in state["models"] if x in ModelManager().get_all_model_names()
            ]
        self._logger.info(f"Models: {",".join(x for x in state["models"])}")

        return state

    async def llm(self, state: dict) -> dict:
        check_state(state, {"code_table", "targets", "point"})
        self._logger.info("Entered Extender.llm")

        point: str = state.get("point", "")
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""Your goal is to generate data blob capable of triggering vulnerability when passed as the first argument of {CP().target_method(state["harness_id"])} within the given code under <CODE> label.
Vulnerability is triggered when maliciously crafted input is reached at ({point}).
To achieve the goal, please identify all of the essential lines of code for the file listed under the <FILE> label.
Your response must include a JSON format, structured as follows:
```json
[[start_line1, end_line1], [start_line2, end_line2], ...]
```
For example, if lines 3 to 6 and line 8 are required, write it as follows.
```json
[[3, 6], [8, 8]]
```"""
            )
        ]
        code_table: dict[str, list[tuple[int, int]]] = state.get("code_table", {})
        targets: list[str] = state.get("targets", [])

        async def extend_per_file(
            code_table: dict, file: str, messages: list[BaseMessage]
        ) -> Optional[dict]:
            self._logger.info(f"- Target: {file}")
            copied_code_table = copy.deepcopy(code_table)
            copied_code_table[file] = [(1, sys.maxsize)]
            code: str = await self.__reader.read_by_table(copied_code_table)
            copied_messages = copy.deepcopy(messages)
            copied_messages.append(
                HumanMessage(
                    content=f"""<FILE>
{file}

<CODE>
{code}"""
                )
            )
            for i in range(0, 3):
                for model_name in random.sample(
                    state["models"], k=len(state["models"])
                ):
                    try:
                        return await ModelManager().invoke_atomic(
                            copied_messages, model_name, JsonParser(), agent="extender"
                        )
                    except LLMRetriable:
                        await asyncio.sleep(60)
                    except Exception:
                        break
            return {}

        result: dict[str, dict] = {
            x: await extend_per_file(code_table, x, messages) for x in targets
        }
        result: dict[str, dict] = {
            key: value for key, value in result.items() if value is not None
        }
        state["llm_result"] = result
        return state

    async def extend_method(self, state: dict) -> dict:
        check_state(state, {"llm_result", "new_code_table", "point"})
        llm_result: dict = state.get("llm_result", {})
        new_code_table: dict = state.get("new_code_table", {})

        @async_safe([], SEVERITY.WARNING, "Extender")
        async def extend_per_file(
            file: str, ranges: list[tuple[int, int]]
        ) -> list[tuple[int, int]]:
            query: str = f"""
cpg.method
    .where(_.filenameExact("{file}"))
    .where(_.or(
        {",\n        ".join([f"_.and(_.lineNumberLte({end}), _.lineNumberGte({begin}))" for begin, end in ranges])}))
    .map(m => (m.lineNumber, m.lineNumberEnd))
    .collect {{
        case (Some(start), Some(end)) => Map("start" -> start, "end" -> end)
        }}
       .l

"""
            result: list = await Joern().run_query(query)
            result = [
                (x["start"], x["end"]) for x in result if "start" in x and "end" in x
            ]
            return result

        extended: dict[str, list[tuple[int, int]]] = {
            x: await extend_per_file(x, y) for x, y in llm_result.items()
        }
        new_code_table: dict = self.update_code_table(new_code_table, extended)
        state["new_code_table"] = new_code_table
        return state

    async def extend_member(self, state: dict) -> dict:
        check_state(state, {"end", "new_code_table", "start"})

        end: CodeLocation = state.get("end", None)
        new_code_table: dict = state.get("new_code_table", {})
        start: CodeLocation = state.get("start", None)
        if start is None or end is None:
            return state

        try:
            query: str = f"""
    def toInt(v : Integer | Int): Int = {{
        v match {{
            case i: Int => i
            case j: java.lang.Integer => j.intValue()
        }}
    }}
    val fieldInRange = cpg.fieldAccess
        .where(_.method.filenameExact(\"{start.path}\"))
        .where(_.lineNumberGte({start.line}))
        .where(_.lineNumberLte({end.line}))
        .where(_.argument(1).code("this"))
        .distinctBy(_.argument(2).code)
        .l
    val fieldInClass = fieldInRange.
        map(x => x.typeDecl.fieldAccess.where(_.argument(2).codeExact(x.argument(2).code)).l).flatten
    val methods = fieldInClass
        .whereNot(_.method.nameExact("<init>"))
        .method.distinctBy(_.fullName).l ++ fieldInClass
        .where(_.method.nameExact("<init>"))
        .filter(x => (toInt(x.lineNumber.getOrElse(-1))) >= toInt(x.method.lineNumber.getOrElse(-1)))
        .filter(x => (toInt(x.lineNumber.getOrElse(-1))) <= toInt(x.method.lineNumberEnd.getOrElse(-1)))
        .method.l
    val members = fieldInClass
        .where(_.method.nameExact("<init>"))
        .filter(x => (toInt(x.lineNumber.getOrElse(-1)) < toInt(x.method.lineNumber.getOrElse(-1))) || (toInt(x.lineNumber.getOrElse(-1)) > toInt(x.method.lineNumberEnd.getOrElse(-1))))
        .l
    (methods.map(x => (toInt(x.lineNumber.getOrElse(-1)), toInt(x.lineNumberEnd.getOrElse(-1)))) ++
        members.map(x => (toInt(x.lineNumber.getOrElse(-1)), toInt(x.lineNumber.getOrElse(-1)))))
        .filter(x => x._1 != -1 && x._2 != -1)
        .map {{ case (start, end) => Map("start" -> start, "end" -> end) }}
    """
            extended: dict[str, list[tuple[int, int]]] = {
                start.path: [
                    (int(x.get("start", -1)), int(x.get("end", -1)))
                    for x in await Joern().run_query(query)
                ]
            }
            new_code_table = self.update_code_table(new_code_table, extended)
            state["new_code_table"] = new_code_table
        except Exception:
            pass
        return state

    def update_code_table(self, table_1: dict, table_2: dict) -> dict:
        merged_table: dict = defaultdict(list)

        for table in [table_1, table_2]:
            for path, intervals in table.items():
                merged_table[path].extend(intervals)

        def merge_ranges(ranges: list):
            if not ranges:
                return []

            ranges.sort()
            merged: list = [ranges[0]]

            for current in ranges[1:]:
                last_start, last_end = merged[-1]
                current_start, current_end = current

                if current_start <= last_end:
                    merged[-1] = (last_start, max(last_end, current_end))
                else:
                    merged.append(current)

            return merged

        result: dict = {}
        for path, intervals in merged_table.items():
            result[path] = merge_ranges(intervals)

        return result

    def print_code_table(self, table: dict[str, list[tuple[int, int]]]) -> str:
        return "\n".join(
            [
                f"{file}: {", ".join([f"({begin}~{end})" for begin, end in parts])}"
                for file, parts in table.items()
            ]
        )
