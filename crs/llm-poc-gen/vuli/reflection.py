import asyncio
import copy
import logging
from functools import reduce
from typing import Optional, TypedDict

from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.messages.system import SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledGraph

from vuli.agents.common import check_state
from vuli.agents.parser import JsonParser
from vuli.calltree import CallTree, CallTreePathFinder
from vuli.codereader import BaseReader
from vuli.common.decorators import SEVERITY, async_safe
from vuli.cp import CP
from vuli.joern import Joern
from vuli.model_manager import ModelManager
from vuli.task import TaskHandler


class State(TypedDict):
    harness_path: str
    exclude: list[int]

    cost: float
    saved_cost: float
    paths: list[list[int]]
    result: list[tuple[list[int], list[int]]]
    targets: list[int]
    unreachable_targets: list[int]
    verified_paths: list[list[int]]


class ReflectionGraph:
    def __init__(self):
        self._logger = logging.getLogger("reflection solver")

    def compile(self) -> CompiledGraph:
        graph = StateGraph(State)
        graph.add_node("prepare", self.prepare)
        graph.add_node("scan", self.scan)
        graph.add_node("callgraph", self.callgraph)
        graph.add_node("sta", self.sta)
        graph.add_node("llm", self.llm)
        graph.add_node("solve", self.solve)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "scan")
        graph.add_edge("scan", "callgraph")
        graph.add_edge("callgraph", "sta")
        graph.add_edge("sta", "llm")
        graph.add_edge("llm", "solve")
        graph.add_edge("solve", END)
        return graph.compile()

    def prepare(self, state: dict) -> dict:
        state["cost"] = 0.0
        state["saved_cost"] = 0.0
        return state

    async def scan(self, state: dict) -> dict:
        exclude: list[int] = state.get("exclude", [])
        query: str = """
cpg.call
    .where(_.methodFullName("^java.lang.reflect.Method.invoke.*"))"""
        if len(exclude) > 0:
            query += f"""
    .whereNot(_.or({",".join([f"_.id({x}L)" for x in exclude])}))"""
        query += """
    .id.l"""
        query_result: list[int] = await Joern().run_query(query)
        state["targets"] = query_result
        self._logger.info(
            f"Reflection Solver Found {len(state.get("targets", []))} targets"
        )
        return state

    async def callgraph(self, state: dict) -> dict:
        check_state(state, {"targets"})

        targets: list[int] = state.get("targets", [])
        harness_path: str = state.get("harness_path", "")
        harness_name: str = CP().get_harness_name(harness_path)
        identified_paths: list[list[int]] = []
        unreachable_targets: list[int] = []
        query: str = f"""
cpg.method
    .where(_.filenameExact("{harness_path}"))
    .where(_.nameExact("{CP().target_method(harness_name)}"))
    .map(_.id)
    .l
"""
        entry: list[int] = await Joern().run_query(query)
        query: str = f"""
cpg.call
    .where(_.or({", ".join([f"_.id({x}L)" for x in targets])}))
    .map(x => (x.method.id, x.id))
    .groupBy(_._1)
    .view.mapValues(_.map(_._2))
    .toMap
"""
        table: dict[int, set[int]] = await Joern().run_query(query)

        finder = CallTreePathFinder(await CallTree().get_graph())
        for method, calls in table.items():
            paths: list[list[int]] = [
                await asyncio.to_thread(finder.find_path, y, int(method)) for y in entry
            ]
            paths: list[list[int]] = [x for x in paths if x is not None]
            if len(paths) == 0:
                unreachable_targets.extend(calls)
                continue
            for path in paths:
                for call in calls:
                    new_path: list[int] = copy.deepcopy(path)
                    new_path.append(call)
                    identified_paths.append(new_path)

        state["paths"] = identified_paths
        state["unreachable_targets"] = unreachable_targets
        self._logger.info(
            f"Reflection Solver found {len(state.get("paths", []))} solvable paths"
        )
        return state

    async def sta(self, state: dict) -> dict:
        check_state(state, {"paths"})
        paths: list[list[int]] = state.get("paths", [])
        total_path: int = len(paths)
        verified_paths: list[int] = []
        unverified_paths: list[int] = []
        for idx, path in enumerate(paths):
            has_flow: bool = len(await self._sta_for_callflow(path)) > 0
            self._logger.info(
                f"Reflection Solver STA Path Verifier {idx + 1}/{total_path}: {has_flow}"
            )
            if len(await self._sta_for_callflow(path)) > 0:
                verified_paths.append(path)
            else:
                unverified_paths.append(path)
        state["verified_paths"] = verified_paths
        state["paths"] = unverified_paths
        self._logger.info(
            f"Reflection Solver STA Path Verifier Summary (verified: {len(state.get("verified_paths", []))}, total: {total_path})"
        )
        return state

    def llm(self, state: dict) -> dict:
        # TODO
        # So far, this will reject all callflows.
        check_state(state, {"paths", "unreachable_targets"})
        paths: list[list[int]] = state.get("paths", [])
        unreachable_targets: list[int] = state.get("unreachable_targets", [])
        unreachable_targets.extend([x[-1] for x in paths if len(x) > 0])
        unreachable_targets = list(dict.fromkeys(unreachable_targets))
        state["unreachable_targets"] = unreachable_targets
        state["paths"] = []
        return state

    async def _sta_for_callflow(self, callflow: list[int]) -> list[list[int]]:
        def make_query(ids: list[int]) -> str:
            return f"""cpg.ids({",".join([str(x) for x in ids])})
    .collect{{
        case x: Method => x.parameter.l
        case x: io.shiftleft.codepropertygraph.generated.nodes.Call => x.argument.l
    }}
    .flatten"""

        if len(callflow) < 2:
            return callflow

        table: dict[int, list[list[int]]] = {}
        start: list[int] = [callflow[0]]
        callflow_size: int = len(callflow)
        idx: int = 1

        while True:
            current_idx: int = idx
            idx = idx + 4 if (idx + 4) < callflow_size else callflow_size
            if current_idx == idx:
                break

            sink: int = callflow[idx - 1]
            query: str = f"""
def src = {make_query(start)}
def sink = {make_query([sink])}
sink.reachableByFlows(src)
    .map(_.elements)
    .map(_.id.l)
    .l"""
            paths: Optional[list[list[int]]] = await Joern().run_query(
                query, timeout=10, safe=False
            )
            if paths is None:
                paths = [[]]
            paths: list[list[int]] = [x for x in paths if len(x) > 0]
            # NOTE: Simple filtering to avoid recursion
            paths: list[list[int]] = [x for x in paths if not x[-1] in table]

            start: list[int] = []
            for path in paths:
                sink: int = path[-1]
                table.setdefault(sink, []).append(path)
                start.append(sink)

        def make_result(path: list[int], table) -> list[list[int]]:
            if len(path) == 0:
                return [path]

            src: int = path[0]
            next_paths: list[list[int]] = table.get(src, [])
            next_paths = [x[:-1] for x in next_paths]
            [x.extend(path) for x in next_paths]
            return next_paths if len(next_paths) > 0 else [path]

        result_paths: list[list[int]] = []
        query: str = f"""
{make_query([callflow[-1]])}
    .map(_.id)
    .l
"""
        start: list[int] = await Joern().run_query(query)
        next_paths: list[list[int]] = []
        [next_paths.extend(table[x]) for x in start if x in table]
        while len(next_paths) > 0:
            paths: list[list[int]] = copy.deepcopy(next_paths)
            next_paths = []
            for path in paths:
                new_paths: list[list[int]] = make_result(path, table)
                if len(new_paths) == 0:
                    continue
                if len(new_paths) == 1 and new_paths[0] == path:
                    result_paths.extend(new_paths)
                    continue
                next_paths.extend(new_paths)
        query: str = f"""
{make_query([callflow[0]])}
    .map(_.id)
    .l"""
        start: set[int] = set(await Joern().run_query(query))
        result_paths: list[int] = [
            x for x in result_paths if len(x) > 0 and x[0] in start
        ]
        return result_paths

    async def solve(self, state: dict) -> dict:
        """
        Args
            verified
                List of may-reachable paths
        Result
            cost
                LLM costs
            saved cost
                LLM costs but not spent because of cache
            result
                List of call edges through targets. To store one-to-many
                relationship, the type is Tuple[int, list[int]]
        """
        check_state(state, {"verified_paths"})

        verified_paths: list[list[int]] = state.get("verified_paths", [])
        if len(verified_paths) == 0:
            return

        cost: float = 0.0
        saved_cost: float = 0.0
        result: list[tuple[list[int], list[int]]] = []
        for idx, path in enumerate(verified_paths):
            self._logger.info(f"Solving ({idx + 1}/{len(verified_paths)})")
            new_result: dict = await self.__solve_for_cf(path)
            new_cost: float = new_result.get("cost", 0.0)
            new_saved_cost: float = new_result.get("saved_cost", 0.0)
            cost += new_cost
            saved_cost += new_saved_cost
            new_edge = new_result.get("result", ([], []))
            if len(new_edge[0]) > 0 and len(new_edge[1]) > 0:
                result.append(new_edge)

        solved: list[int] = state.get("solved", [])
        solved.extend([x[-1] for x in verified_paths if len(x) > 0])
        solved = list(dict.fromkeys(solved).keys())
        state["cost"] += cost
        state["saved_cost"] += saved_cost
        state["solved"] = solved
        state["result"] = result
        return state

    async def __solve_for_cf(self, cf: list[int]) -> dict:
        result: dict = {"result": ([], []), "cost": 0.0, "saved_cost": 0.0}

        if len(cf) == 0:
            return result

        model_name: str = ModelManager().resolve_model("gpt-4.1")

        system_message_1: BaseMessage = SystemMessage(
            content="""I want to know which functions can be called via reflection in the given code.
Analyze the code and determine which class's methods can be invoked or which method names are callable.
code is given under the label <CODE>.
Do Not INCLUDE pacakage name, just answer className.
You MUST respond with the necessary class information to solve problem in the following format.

```json
{
   "name": "ClassName"
}
```
"""
        )

        query: str = f"""
  cpg.ids({",".join([str(x) for x in cf])})
    .collect {{
      case x: Method  => x
      case x: CfgNode => x.method
    }}
    .map(x => x.filename -> (x.lineNumber, x.lineNumberEnd))
    .collect {{
      case (filename, (Some(start), Some(end))) => filename -> (start, end)
    }}
    .groupBy(_._1)
    .view.map {{ case (filename, entries) =>
      val ranges = entries.map(_._2)
        .distinct
        .sortBy(_._1)
        .map {{ case (start, end) => Map("start" -> start, "end" -> end) }}
      Map("filename" -> filename, "lineInfo" -> ranges)
    }}
    .toList"""
        query_results: list = await Joern().run_query(query)
        code_table = {
            result.get("filename", ""): [
                (line.get("start", -1), line.get("end", -1))
                for line in result.get("lineInfo", [])
            ]
            for result in query_results
        }

        code: str = await BaseReader(CP().source_dir).read_by_table(code_table)
        messages: list[BaseMessage] = [system_message_1]
        messages.append(HumanMessage(content=f"<CODE>\n{code}"))
        try:
            model_result: dict = await ModelManager().invoke_atomic(
                messages, model_name, JsonParser(), agent="reflection"
            )
        except Exception as e:
            self._logger.warning(f"Skip Exception: {e}")
            return result

        name: str = model_result.get("name", "")
        query: str = f"""
cpg.typeDecl
    .where(_.nameExact("{name}"))
    .method
    .fullName
    .distinct
    .l
"""
        method_names: list[str] = await Joern().run_query(query)
        if len(method_names) == 0:
            return result

        messages.append(
            HumanMessage(
                content=f"""The following methods specified under <METHODS> are defined in the class.
Each method is written in the following format:
{{fully qualified package, class and method name}}:{{return type}}({{parameter types}})
Analyze the parameters of the invoke function and the given method by referring to the previous conversation, then respond.
Respond in the format below, specifying what can be called while keeping the full names exactly the same as above.

Step-by-step Instructions (CoT):

1. Infer invoke function's parameters and return type based on prior discussions.
2. Analyze the given method to determine its parameters and return type.
3. Match the analyzed data to identify which method calls can be made using invoke.
4. Generate a list of valid method calls based on the matched parameters and return types.

```json
{{
  "methods": [
    "{{fully qualified package, class and method name}}:{{return type}}({{parameter types}}"
    "...",
  ]
}}
```
<METHOD>
{"\n".join(method_names)}"""
            )
        )
        try:
            model_result: dict = await ModelManager().invoke(
                messages, model_name, JsonParser(), agent="reflection"
            )
        except Exception as e:
            self._logger.warning(f"Skip Exception: {e}")
            return result

        method_names: list[str] = model_result.get("methods", [])
        query: str = f"""
Map(
  "src" -> cpg.ids({cf[-1]})
    .collect {{
      case x: Method  => x
      case x: CfgNode => x.method
    }}
    .id.l,
  "dest" -> cpg.method
    .where(_.or({", ".join([f'_.fullNameExact("{x}")' for x in method_names])}))
    .id.l
)
"""
        edges: dict = await Joern().run_query(query)
        result["result"] = (edges.get("src", []), edges.get("dest", []))

        return result

    def need_scan(self, state: dict) -> bool:
        return len(state.get("targets", [])) == 0


class ReflectionSolver(TaskHandler):
    def __init__(self, harnesses: list[str]):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._harnesses = harnesses

    async def run(self) -> None:
        exclude: set[int] = set()
        graph = ReflectionGraph().compile()
        [
            await self._solve_per_harness(graph, harness, exclude)
            for harness in self._harnesses
        ]

    @async_safe(None, SEVERITY.WARNING, "SolveReflection")
    async def _solve_per_harness(
        self, graph: CompiledGraph, harness: str, exclude: set[int]
    ) -> None:
        self._logger.info(f"Start Reflection Solver[harness={harness}]")
        result: dict = await graph.ainvoke(
            {
                "harness_path": CP().get_harness_path(harness),
                "exclude": list(exclude),
            }
        )
        edges: list[tuple[list[int], list[int]]] = result.get("result", [])
        verified: list = result.get("verified_paths", [])

        exclude |= set({x[-1] for x in verified if len(x) > 0})
        num_edges: int = reduce(lambda y, x: y + (len(x[0]) * len(x[1])), edges, 0)
        self._logger.info(
            f"Finish Reflection Solver[new edges={num_edges}, harness={harness}"
        )
        [
            await CallTree().insert(src, set(dsts))
            for srcs, dsts in edges
            for src in srcs
        ]
