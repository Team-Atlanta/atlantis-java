import copy
import json
import logging
import re
from pathlib import Path
from typing import TypedDict

from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.messages.system import SystemMessage
from langchain_core.output_parsers.base import BaseOutputParser
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledGraph

from vuli.agents.common import check_state
from vuli.codereader import BaseReader
from vuli.model_manager import ModelManager
from vuli.struct import CodeLocation, CodePoint, LLMParseException


class State(TypedDict):
    code_table: dict
    path: list[CodePoint]
    point: CodeLocation
    cost: float
    saved_cost: float
    messages: list[BaseMessage]
    result: bool


class Parser(BaseOutputParser[str]):
    def parse(self, text: str) -> str:
        try:
            results: list[dict] = [
                json.loads(x) for x in re.findall(r"```json\n(.*?)```", text, re.DOTALL)
            ]
            results: list[str] = [x.get("answer", "") for x in results if "answer" in x]
            results: list[str] = [x for x in results if len(x) > 0]
            return results[0]
        except Exception:
            raise LLMParseException()


class PathValidator:
    def __init__(self, source_dir: Path):
        self._source_dir: Path = source_dir
        self._logger = logging.getLogger("path_validator")
        self._system_message: BaseMessage = SystemMessage(
            content="""Let's do a taint analysis starting with the first argument of fuzzTestOneInput(byte[] data) as the source of tainted data.
The sink is the parameter at the location indicated by `point`.

You MUST answer following the rule:
If the parameter exactly matching the line and column indicated by `point` is related to the tainted input, answer YES.
If the code matching the line indicated by `point` is controlled by the tainted input, but it is certain that the input is not influenced to the parameter, answer NO.
If it is certain that the tainted data does not even reach the code line, answer NO.
If it's unclear from the provided information whether tainted data influences the parameter, answer IDK.

You can refer to `path` as the larger context(a.k.a shortest path from fuzzTestOneInput to `v_point`).

Please include follwoing json format at the end of your answer.
```json
{{
  "answer": "YES" or "NO" or "IDK"
}}
```"""
        )

    def compile(self) -> CompiledGraph:
        graph = StateGraph(State)
        graph.add_node("prepare", self.prepare)
        graph.add_node("validate", self.validate)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "validate")
        graph.add_edge("validate", END)
        return graph.compile()

    def prepare(self, state: dict) -> dict:
        state["cost"] = 0.0
        state["messages"] = [self._system_message]
        state["result"] = False
        state["saved_cost"] = 0.0
        return state

    async def validate(self, state: dict) -> dict:
        check_state(state, {"code_table", "messages"})
        code_table: dict = state.get("code_table", {})
        messages = copy.deepcopy(state.get("messages", []))

        code: str = await BaseReader(self._source_dir).read_by_table(code_table)
        path: list[CodePoint] = state.get("path", [])
        point: CodeLocation = state.get("point", None)
        if not isinstance(point, CodeLocation):
            raise RuntimeError("Invalid Input (point)")
        path_msg: list[str] = [f"path: {x.path}, line: {x.line}" for x in path]
        point_msg: str = f"path: {point.path}, line: {point.line}"
        if point.column != -1:
            point_msg += f", column: {point.column}"
        message: HumanMessage = HumanMessage(
            content=f"""<point>
{point_msg}

<path>
{"\n".join(path_msg)}

<code>
{code}
"""
        )
        messages.append(message)
        model_name: str = ModelManager().resolve_model("gpt-4.1")
        model_result: dict = await ModelManager().invoke(messages, model_name, Parser(), agent="pathvalidator")
        cache: bool = model_result.get("cache", False)
        cost: float = model_result.get("cost", 0.0)
        result: bool = model_result.get("result", "OK")
        if cache:
            state["saved_cost"] += cost
        else:
            state["cost"] += cost
        state["result"] = result

        summary_msg: str = f"""Path Validation ======
Validity: {state["result"]}
Cost: (Spent: {state["cost"]}, Saved: {state["saved_cost"]})
Point: {point_msg}
Path:
{"\n".join([f"  # {idx + 1} {x}" for idx, x in enumerate(path_msg)])}
==========================
"""
        self._logger.info(summary_msg)
        return state
