import logging
from typing import Optional, TypedDict

from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledGraph

from vuli.agents.extender import Extender
from vuli.agents.parser import JsonParser
from vuli.blobgen import BlobGeneratorResult, EvaluatorResult, SeedGenerator
from vuli.codereader import BaseReader
from vuli.cp import CP
from vuli.debugger import JDB
from vuli.joern import Joern
from vuli.model_manager import ModelManager
from vuli.struct import CodeLocation, CodePoint, VulInfo
from vuli.verifier import DebuggerVerifier


class State(TypedDict):
    candidate: VulInfo
    code_table: dict
    externals: list[str]
    harness_id: str
    history: dict
    point: str
    prev: BlobGeneratorResult
    reached: bool
    models: list[str]


class GeneratorAgent:
    def __init__(self, seed_generator: SeedGenerator, iter: int = 2):
        self._logger = logging.getLogger("Generator")
        self._log_prefix: str = ""
        self._seed_generator: SeedGenerator = seed_generator
        self._extender = Extender(BaseReader(CP().source_dir)).compile()
        self._iter: int = iter

    def _log(self, msg: str) -> str:
        if len(self._log_prefix) == 0:
            return msg
        return f"[{self._log_prefix}] {msg}"

    def compile_onetime_gen(self) -> CompiledGraph:
        graph = StateGraph(State)
        graph.add_node("prepare", self.prepare)
        graph.add_node("generate_blob", self.generate_blob)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "generate_blob")
        graph.add_edge("generate_blob", END)
        return graph.compile()

    def compile(self) -> CompiledGraph:
        graph = StateGraph(State)
        graph.add_node("prepare", self.prepare)
        graph.add_node("generate_blob", self.generate_blob)
        graph.add_node("localize", self.localize)
        graph.add_node("extend", self.extend)
        graph.add_node("external", self.external)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "generate_blob")
        graph.add_conditional_edges(
            "generate_blob", self.need_regenerate, {True: "localize", False: END}
        )
        graph.add_edge("localize", "extend")
        graph.add_edge("extend", "external")
        graph.add_edge("external", "generate_blob")
        return graph.compile()

    async def localize(self, state: dict) -> dict:
        last_visit, next_visit = state["prev"].localized
        if last_visit is None or next_visit is None:
            return state
        if last_visit.method == next_visit.method:
            return state
        joern_query: str = f"""
cpg.method
    .where(_.filenameExact("{last_visit.path}"))
    .where(_.lineNumberLte({last_visit.line}))
    .where(_.lineNumberEndGte({last_visit.line}))
    .fullName.headOption.getOrElse("")
"""
        method_name: str = await Joern().run_query(joern_query)
        if method_name == "":
            return state

        blob: bytes = state.get("blob", b"")
        code_table: dict = state.get("code_table", {})
        harness_id: int = state.get("harness_id", -1)
        harness_path: str = CP().get_harness_path(harness_id)
        visited_lines: list[CodeLocation] = await DebuggerVerifier(
            JDB()
        ).visited_for_method(blob, harness_path, method_name)
        code: str = await BaseReader(CP().source_dir).read_by_table(code_table)
        message: BaseMessage = HumanMessage(
            content=f"""
The given Blob failed to reach Function B from Function A in the provided code.
Please identify where the program execution goes wrong within Function A and provide its file path and line number.
You can check visited lines in order under <Visited Lines> label.
Visited Lines is a list of line number only within Function A.
Your response must include the following JSON format:
```json
{{
   "file_path": "...",
   "start_line": XX,
   "end_line": XX,
}}

<Function A>
{last_visit.method}

<Function B>
{next_visit.method}

<Blob>
{blob}

<Visited Lines>
{", ".join([str(x.line) for x in visited_lines])}

<Code>
{code}
```"""
        )
        try:
            result: dict = await ModelManager().invoke(
                [message], "gpt-4.1", JsonParser(), agent="generator"
            )
        except Exception as e:
            self._logger.warning(f"Skip Exception: {e}")
            return state
        file_path: str = result.get("file_path", "")
        start_line: int = result.get("start_line", -1)
        end_line: int = result.get("end_line", -1)
        if file_path == "" or start_line == -1 or end_line == -1:
            return state

        last_visit = CodePoint(last_visit.path, last_visit.method, start_line)
        next_visit = CodePoint(last_visit.path, last_visit.method, end_line)
        state["localized"] = (last_visit, next_visit)
        self._logger.info(
            self._log(f"Issue: {last_visit.path}, {last_visit.line}~{next_visit.line}")
        )
        return state

    async def extend(self, state: dict) -> dict:
        last_visit, next_visit = state["prev"].localized
        point: str = state["point"]
        if last_visit is None or next_visit is None:
            self._logger.info(self._log("Extender: Not Worked"))
            return state

        extender_state: dict = {
            "code_table": state["code_table"],
            "end": CodeLocation(next_visit.path, next_visit.line),
            "start": CodeLocation(last_visit.path, last_visit.line),
            "targets": list(dict.fromkeys([last_visit.path, next_visit.path]).keys()),
            "point": point,
            "harness_id": state["harness_id"]
        }
        result_state: dict = await self._extender.ainvoke(extender_state)
        result: dict = result_state.get("new_code_table", {})
        if self.__code_table_is_updated(state["code_table"], result):
            state["code_table"] = result
            log_msg = [
                f"{path}: {start}~{end}"
                for path, lines in state.get("code_table", {}).items()
                for start, end in lines
            ]
            self._logger.info(self._log(f"Extender worked:\n{"\n".join(log_msg)}"))
        else:
            self._logger.info(self._log("Extender worked: Nothing Extended"))
        return state

    async def external(self, state: dict) -> dict:
        last_visit, next_visit = state["prev"].localized
        if last_visit is None or (
            next_visit is not None and (last_visit.method != next_visit.method)
        ):
            self._logger.info(self._log("External not worked"))
            return state

        query: str = f"""
cpg.call
    .where(_.method.fullNameExact("{last_visit.method}"))"""
        if next_visit is None:
            query += f"""
    .where(_.lineNumber({last_visit.line}))"""
        else:
            query += f"""
    .where(_.lineNumberGte({last_visit.line}))
    .where(_.lineNumberLt({next_visit.line}))"""
        query += """
    .whereNot(_.methodFullName("^<operator>.*"))
    .where(_.callee.isExternal(true))
    .methodFullName
    .distinct
    .l"""
        externals: list[str] = await Joern().run_query(query)
        state["externals"] = externals
        if len(externals) == 0:
            self._logger.info(self._log("External worked: Nothing found"))
        else:
            log_msg: list[str] = [
                f"{idx + 1} {external}"
                for idx, external in enumerate(state.get("externals", []))
            ]
            self._logger.info(self._log(f"External worked:\n{"\n".join(log_msg)}"))
        return state

    def generate_feedback(
        self,
        localized: tuple[Optional[CodeLocation], Optional[CodeLocation]],
        externals: list[str],
    ) -> str:
        last_visit, next_visit = localized
        if last_visit is None or next_visit is None:
            return ""
        feedback_list: list[str] = [
            f"""There are some statements that execution went wrong between {last_visit.path}:{last_visit.line} and {next_visit.path}:{next_visit.line}.
You MUST specify which statements make execution went wrong and focus on them."""
        ]
        if len(externals) > 0:
            feedback_list.append(
                f"There are some external function calls that may affect the exeuction path. Please check below functions are really affect the execution path and if so try to make blob based on those function behavior.\n-{"\n-".join(externals)}"
            )
        return "\n".join(
            [f"{idx + 1}: {feedback}" for idx, feedback in enumerate(feedback_list)]
        )

    async def generate_blob(self, state: dict) -> dict:
        externals = state.get("externals", [])
        localized: tuple[Optional[CodePoint], Optional[CodePoint]] = state[
            "prev"
        ].localized
        iteration: int = state["history"].setdefault(localized, 0)
        code: str = await BaseReader(CP().source_dir).read_by_table(state["code_table"])
        feedback: str = self.generate_feedback(localized, externals)
        state["history"][localized] = iteration + 1

        result: BlobGeneratorResult = await self._seed_generator.generate(
            code,
            state["harness_id"],
            state["models"],
            state["candidate"].v_paths,
            state["point"],
            feedback,
            state["prev"],
        )
        improve: bool = result.eval.score > state["prev"].eval.score
        if improve:
            state["prev"] = result
        if result.eval.score == 1.0:
            state["reached"] = True
        self._logger.info(
            f"Summary Blob Generation [improve: {improve}, last:{result.localized[0]}, iteration:{iteration}]"
        )
        return state

    def prepare(self, state: dict) -> dict:
        if not isinstance(state.get("candidate", None), VulInfo):
            raise RuntimeError("Invalid Input (candidate)")
        if not isinstance(state.get("code_table", None), dict):
            raise RuntimeError("Invalid Input (code table)")
        if not isinstance(state.get("harness_id", None), str):
            raise RuntimeError("Invalid Input (harness_id)")

        state["externals"] = []
        state["history"] = {}
        state["point"] = (
            f"Path={state["candidate"].v_point.path}, Line={state["candidate"].v_point.line}"
        )
        if state["candidate"].v_point.column != -1:
            state["point"] += f", Column={state["candidate"].v_point.column}"
        state["prev"] = BlobGeneratorResult(
            blob=b"",
            eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
            localized=(None, None),
            model_name="",
            script="",
            prompt=[],
        )

        if len(state.get("models", [])) == 0:
            state["models"] = ModelManager().get_all_model_names()
        else:
            state["models"] = [
                x for x in state["models"] if x in ModelManager().get_all_model_names()
            ]
        self._logger.info(f"Models: {",".join(x for x in state["models"])}")

        state["reached"] = False
        self._log_prefix = (
            f"{state["candidate"].harness_id}->{state["candidate"].v_point}"
        )
        return state

    def need_regenerate(self, state: dict) -> bool:
        iteration: int = state["history"].get(state["prev"].localized, 0)
        return state["reached"] is False and iteration < self._iter

    def __code_table_is_updated(self, previous: dict, after: dict) -> bool:
        if set(previous.keys()) != set(after.keys()):
            return True

        for path in after:
            if sorted(previous.get(path, [])) != sorted(after.get(path, [])):
                return True
        return False
