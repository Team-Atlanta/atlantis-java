import asyncio
import base64
import logging
import random
import re
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

import aiofiles
import pyjson5
from langchain_core.messages import BaseMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.messages.system import SystemMessage
from langchain_core.output_parsers.base import BaseOutputParser
from pydantic import BaseModel, Field

from vuli.agents.parser import PythonParser
from vuli.blackboard import Blackboard
from vuli.common.decorators import SEVERITY, async_safe
from vuli.common.setting import Setting
from vuli.common.singleton import Singleton
from vuli.cp import CP
from vuli.debugger import JDB
from vuli.joern import Joern
from vuli.model_manager import ModelManager
from vuli.struct import (
    CodeLocation,
    CodePoint,
    LLMParseException,
    LLMRetriable,
    Sanitizer,
)
from vuli.util import async_process_run_and_exit
from vuli.verifier import DebuggerVerifier, GDBVerifier


class EvaluatorResult(BaseModel):
    crash: bool
    last_visit: int
    score: float


class BlobEvaluator(ABC):
    def __init__(self, verifier: DebuggerVerifier):
        self._debugger_verifier = verifier

    @abstractmethod
    async def evaluate(
        self, blob: bytes, harness_path: Path, path: list[CodePoint]
    ) -> EvaluatorResult:
        pass

    async def _get_last_visit(
        self, blob: bytes, harness_path: Path, path: list[CodePoint]
    ) -> int:
        visited: list[CodeLocation] = await self._debugger_verifier.visited_for_path(
            blob, harness_path, path
        )
        last_visit: int = -1
        path_size: int = len(path)
        for idx_visited in range(0, len(visited)):
            loc_visited: CodeLocation = visited[idx_visited]
            for idx_expected in range(last_visit + 1, path_size):
                loc_expected: CodePoint = path[idx_expected]
                if (
                    loc_visited.path == loc_expected.path
                    and loc_visited.line == loc_expected.line
                ):
                    last_visit = idx_expected
                    break
            if idx_expected == path_size:
                break
        return last_visit


class SeedEvaluator(BlobEvaluator):
    def __init__(self, verifier: DebuggerVerifier):
        super().__init__(verifier=verifier)
        self._logger = logging.getLogger(self.__class__.__name__)

    async def evaluate(
        self,
        blob: bytes,
        harness_path: Path,
        path: list[CodePoint],
    ) -> EvaluatorResult:
        last_visit: int = await self._get_last_visit(blob, harness_path, path)
        score: float = (last_visit + 1) / len(path)
        return EvaluatorResult(crash=False, last_visit=last_visit, score=score)


class PoVEvaluator(BlobEvaluator):
    def __init__(
        self,
        verifier: DebuggerVerifier = DebuggerVerifier(JDB()),
        use_jazzer: bool = True,
    ):
        super().__init__(verifier=verifier)
        self._use_jazzer = use_jazzer
        self._logger = logging.getLogger(self.__class__.__name__)

    async def evaluate(
        self,
        blob: bytes,
        harness_path: Path,
        path: list[CodePoint],
    ) -> EvaluatorResult:
        crash = await self._debugger_verifier.verify(
            blob, harness_path, self._use_jazzer
        )
        score: float = 1.0 if crash is True else 0.0
        last_visit: int = -1
        if self._use_jazzer is True:
            last_visit: int = await self._get_last_visit(blob, harness_path, path)
        return EvaluatorResult(crash=crash, last_visit=last_visit, score=score)


class BlobGeneratorResult(BaseModel):
    blob: bytes
    eval: EvaluatorResult
    localized: tuple[Optional[CodePoint], Optional[CodePoint]]
    model_name: str
    script: str
    prompt: list[BaseMessage]


class BlobGenerator:
    def __init__(self, evaluator=BlobEvaluator):
        self._logger = logging.getLogger("BlobGenerator")
        self._evaluator = evaluator

    async def generate(
        self,
        path: list[CodePoint],
        harness_id: str,
        harness_path: str,
        messages: list[BaseMessage],
        parser: BaseOutputParser[Any],
        model_name: str,
    ) -> BlobGeneratorResult:
        try:
            model_result: list[dict] = await ModelManager().invoke(
                messages, model_name, parser, agent="blobgen"
            )
        except Exception as e:
            self._logger.warning(f"Skip Exception: {e}")
            model_result: list[dict] = []

        results: list[tuple[dict, dict]] = [
            (x, await self._evaluator.evaluate(x.get("blob", b""), harness_path, path))
            for x in model_result
        ]
        [
            await Blackboard().add_seed(
                harness_id, parse_result.get("blob", b""), eval_result.score
            )
            for parse_result, eval_result in results
        ]
        if len(results) == 0:
            return BlobGeneratorResult(
                blob=b"",
                eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
                localized=(None, None),
                model_name=model_name,
                script="",
                prompt=messages,
            )
        parsed_result, eval_result = max(results, key=lambda x: x[1].score)
        blob: bytes = parsed_result.get("blob", b"")
        script: str = parsed_result.get("script", "")
        last_visit: Optional[CodePoint] = (
            path[eval_result.last_visit] if eval_result.last_visit >= 0 else None
        )
        next_visit: Optional[CodePoint] = (
            path[eval_result.last_visit + 1]
            if eval_result.last_visit + 1 < len(path)
            else None
        )
        last_visit, next_visit = await self._post_process_visit(last_visit, next_visit)
        return BlobGeneratorResult(
            blob=blob,
            eval=eval_result,
            localized=(last_visit, next_visit),
            model_name=model_name,
            script=script,
            prompt=messages,
        )

    async def generate2(
        self,
        path: list[CodePoint],
        harness_id: str,
        harness_path: str,
        messages: list[BaseMessage],
        parser: BaseOutputParser[Any],
        model_names: list[str],
    ) -> BlobGeneratorResult:
        max_retry: int = 3
        ban_model: set[str] = set()
        for i in range(0, max_retry):
            best_result: Optional[BlobGeneratorResult] = None
            for model_name in random.sample(model_names, k=len(model_names)):
                if model_name in ban_model:
                    continue
                try:
                    result: Optional[BlobGeneratorResult] = (
                        await self._create_blob_generator_result(
                            messages, model_name, parser, path, harness_id, harness_path
                        )
                    )
                    if result is None:
                        ban_model.add(model_name)
                        continue
                except LLMRetriable:
                    continue

                if best_result is None or result.eval.score > best_result.eval.score:
                    best_result = result

                if best_result.eval.score == 1.0:
                    break

            if best_result is not None:
                break

            if len(set(model_names) - ban_model) == 0:
                break

            self._logger.info(
                f"Blob Generation Failed from All Models. Restart after 60 seconds (retry: {i + 1}/{max_retry})"
            )
            await asyncio.sleep(60)

        if best_result is None:
            self._logger.info(
                "Blob Generation Failed from All Models within Retry Limit"
            )
            best_result = BlobGeneratorResult(
                blob=b"",
                eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
                localized=(None, None),
                model_name="",
                script="",
                prompt=messages,
            )
        return best_result

    @async_safe(None, SEVERITY.ERROR, "BlobGenerator")
    async def _create_blob_generator_result(
        self,
        messages: list[BaseMessage],
        model_name: str,
        parser: BaseOutputParser[Any],
        path: list[CodePoint],
        harness_id: str,
        harness_path: str,
    ) -> Optional[BlobGeneratorResult]:
        """
        raises LLMRetriable
        """
        try:
            model_output: list[dict] = await ModelManager().invoke_atomic(
                messages, model_name, parser, agent="blobgen"
            )
        except LLMParseException:
            self._logger.info(
                f"Blob Generation Failed [reason=Parsing Failed, model={model_name}]"
            )
            return BlobGeneratorResult(
                blob=b"",
                eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
                localized=(None, None),
                model_name=model_name,
                script="",
                prompt=messages,
            )
        except LLMRetriable as e:
            raise e
        except Exception as e:
            self._logger.exception(
                f"Blob Generation Failed [reason=LLM Failed, model={model_name}, "
                f"exc={e.__class__.__name__}: {e}]"
            )
            return None

        try:
            results: list[tuple[dict, dict]] = [
                (
                    x,
                    await self._evaluator.evaluate(
                        x.get("blob", b""), harness_path, path
                    ),
                )
                for x in model_output
            ]
            [
                await Blackboard().add_seed(
                    harness_id, parse_result.get("blob", b""), eval_result.score
                )
                for parse_result, eval_result in results
            ]
            if len(results) == 0:
                self._logger.info(
                    f"Blob Generation Failed [reason=Evaluation Failed, model={model_name}]"
                )
                return BlobGeneratorResult(
                    blob=b"",
                    eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
                    localized=(None, None),
                    model_name=model_name,
                    script="",
                    prompt=messages,
                )
            parsed_result, eval_result = max(results, key=lambda x: x[1].score)
            blob: bytes = parsed_result.get("blob", b"")
            script: str = parsed_result.get("script", "")
            last_visit: Optional[CodePoint] = (
                path[eval_result.last_visit] if eval_result.last_visit >= 0 else None
            )
            next_visit: Optional[CodePoint] = (
                path[eval_result.last_visit + 1]
                if eval_result.last_visit + 1 < len(path)
                else None
            )
            last_visit, next_visit = await self._post_process_visit(
                last_visit, next_visit
            )
            self._logger.info(
                f"Blob Generation Succeed [model={model_name}, score={eval_result.score}, blob={blob[0:128] + (b"..." if len(blob) > 128 else b"")}]"
            )
            return BlobGeneratorResult(
                blob=blob,
                eval=eval_result,
                localized=(last_visit, next_visit),
                model_name=model_name,
                script=script,
                prompt=messages,
            )
        except Exception as e:
            self._logger.info(
                f"Blob Generation Failed [reason=Unexpected, model={model_name}, detail={e.__class__.__name__}: {e}]"
            )
            return BlobGeneratorResult(
                blob=b"",
                eval=EvaluatorResult(crash=False, last_visit=-1, score=0.0),
                localized=(None, None),
                model_name=model_name,
                script="",
                prompt=messages,
            )

    async def _post_process_visit(
        self, last_visit: Optional[CodePoint], next_visit: Optional[CodePoint]
    ) -> tuple[Optional[CodePoint], Optional[CodePoint]]:
        # No need to apply heuristic for the case either last_visit or next_visit is None
        if last_visit is None or next_visit is None:
            return (last_visit, next_visit)

        # Need to process only for the case where the methods of last_visit and next_visit is different.
        if last_visit.method == next_visit.method:
            return (last_visit, next_visit)

        query: str = f"""
    cpg.method.fullNameExact("{next_visit.method}").cfgFirst
        .map(node => (node.method.filename, node.lineNumber, node.columnNumber))
        .collect{{case (a, Some(b), Some(c)) =>  Map("filename" -> a, "lineNumber" -> b, "columnNumber" -> c)}}
        .l
    """
        joern_result: list[dict] = await Joern().run_query(query)
        if len(joern_result) == 0:
            # May not happen, but checks anyway.
            return (last_visit, next_visit)

        new_last_visit: CodePoint = CodePoint(
            joern_result[0].get("filename", ""),
            next_visit.method,
            joern_result[0].get("lineNumber", -1),
            joern_result[0].get("columnNumber", -1),
        )
        if len(new_last_visit.path) == 0 or new_last_visit.line == -1:
            # May not happend, but checks anyway.
            return (last_visit, next_visit)

        if new_last_visit == next_visit:
            # We will not change the case where last_visit and next_visit is same.
            return (last_visit, next_visit)

        return (new_last_visit, next_visit)


class SeedGenerator(ABC):
    @abstractmethod
    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        feedback: str = "",
        prev: Optional[BlobGeneratorResult] = None,
    ) -> BlobGeneratorResult:
        pass


class ByteSeedGenerator(SeedGenerator):
    def __init__(self):
        self._logger = logging.getLogger("ByteSeedGenerator")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        feedback: str = "",
        prev: Optional[BlobGeneratorResult] = None,
    ) -> BlobGeneratorResult:
        blob: bytes = prev.blob if isinstance(prev, BlobGeneratorResult) else b""
        script: str = prev.script if isinstance(prev, BlobGeneratorResult) else ""
        harness_path: str = CP().get_harness_path(harness_id)
        content: str = f"<BLOB>\n{blob}\n\n" if len(blob) > 0 else ""
        content += f"<SCRIPT>\n{script}\n\n" if len(script) > 0 else ""
        content += f"<FEEDBACK>\n{feedback}\n\n" if len(feedback) > 0 else ""
        content += f"<POINT>\n{point}\n\n<CODE>\n{code}\n"
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""You MUST write a python script that generates input values for the first parameter of the {CP().target_method(harness_id)} method, ensuring that this value can reach a specific location.
A Python script MUST uses sys.argv[1].
sys.argv[1] is the path of the file where the generated data blob will be stored.
You will get information about CODE, POINT, BLOB, SCRIPT, FEEDBACK.
You MUST analyze CODE to generate python script correctly.
POINT is the code part that should be reached by the generated blob.
BLOB, SCRIPT, FEEDBACK is optional information.
BLOB is the previous generated blob that failed to reach the POINT.
SCRIPT is the python script that generates BLOB.
FEEDBACK is the additional information learned from analyzing previous failure.
You MUST take into account FEEDBACK.
There some tips you may mistake when inferring blob:
- Endianess

You MUST identify both correct and incorrect parts of BLOB and SCRIPT.
Correct parts should be kept, and incorrect parts should be fixed to generate correct python script.
Before writing a python script in your answer, please analyze code step by step using the above guideline and then add python script as result of your analysis."""
            ),
            HumanMessage(content=content),
        ]

        result: BlobGeneratorResult = await BlobGenerator(
            SeedEvaluator(DebuggerVerifier(JDB()))
        ).generate2(
            path, harness_id, harness_path, messages, PythonParser(), model_names
        )
        self._logger.info(
            f"Generated [model={result.model_name}, score={result.eval.score}"
        )
        return result


class FDPType(Enum):
    I8 = 0
    I16 = 1
    U16 = 2
    I32 = 3
    I64 = 4
    BOOL = 5
    F32 = 6
    F64 = 7
    USIZE = 8
    VEC_I8 = 9
    VEC_I16 = 10
    VEC_U16 = 11
    VEC_I32 = 12
    VEC_I64 = 13
    VEC_BOOL = 14
    VEC_USIZE = 15
    STRING = 16


class FDPMeta(BaseModel):
    method: str
    types: list[FDPType]


class FDPParser:
    table = {
        ("consumeByte", 2): FDPMeta(
            method="produce_jbyte_in_range",
            types=[FDPType.I8, FDPType.I8, FDPType.I8],
        ),
        ("consumeShort", 2): FDPMeta(
            method="produce_jshort_in_range",
            types=[FDPType.I16, FDPType.I16, FDPType.I16],
        ),
        ("consumeChar", 2): FDPMeta(
            method="produce_jchar_in_range",
            types=[FDPType.U16, FDPType.U16, FDPType.U16],
        ),
        ("consumeInt", 2): FDPMeta(
            method="produce_jint_in_range",
            types=[FDPType.I32, FDPType.I32, FDPType.I32],
        ),
        ("consumeLong", 2): FDPMeta(
            method="produce_jlong_in_range",
            types=[FDPType.I64, FDPType.I64, FDPType.I64],
        ),
        ("consumeByte", 0): FDPMeta(
            method="produce_jbyte",
            types=[
                FDPType.I8,
            ],
        ),
        ("consumeShort", 0): FDPMeta(
            method="produce_jshort",
            types=[
                FDPType.I16,
            ],
        ),
        ("consumeInt", 0): FDPMeta(
            method="produce_jint",
            types=[
                FDPType.I32,
            ],
        ),
        ("consumeLong", 0): FDPMeta(
            method="produce_jlong",
            types=[
                FDPType.I64,
            ],
        ),
        ("consumeBoolean", 0): FDPMeta(
            method="produce_jbool",
            types=[
                FDPType.BOOL,
            ],
        ),
        ("consumeChar", 0): FDPMeta(
            method="produce_jchar",
            types=[
                FDPType.U16,
            ],
        ),
        ("consumeCharNoSurrogates", 0): FDPMeta(
            method="produce_jchar",
            types=[
                FDPType.U16,
            ],
        ),
        ("consumeProbabilityFloat", 0): FDPMeta(
            method="produce_probability_jfloat",
            types=[
                FDPType.F32,
            ],
        ),
        ("consumeProbabilityDouble", 0): FDPMeta(
            method="produce_probability_jdouble",
            types=[
                FDPType.F64,
            ],
        ),
        ("consumeRegularFloat", 2): FDPMeta(
            method="produce_regular_jfloat_in_range",
            types=[FDPType.F32, FDPType.F32, FDPType.F32],
        ),
        ("consumeRegularDouble", 2): FDPMeta(
            method="produce_regular_jdouble_in_range",
            types=[FDPType.F64, FDPType.F64, FDPType.F64],
        ),
        ("consumeRegularFloat", 0): FDPMeta(
            method="produce_regular_jfloat",
            types=[
                FDPType.F32,
            ],
        ),
        ("consumeRegularDouble", 0): FDPMeta(
            method="produce_regular_jdouble",
            types=[
                FDPType.F64,
            ],
        ),
        ("consumeFloat", 0): FDPMeta(
            method="produce_jfloat",
            types=[
                FDPType.F32,
            ],
        ),
        ("consumeDouble", 0): FDPMeta(
            method="produce_jdouble",
            types=[
                FDPType.F64,
            ],
        ),
        ("consumeBooleans", 0): FDPMeta(
            method="produce_jbools",
            types=[
                FDPType.VEC_BOOL,
            ],
        ),
        ("consumeBytes", 1): FDPMeta(
            method="produce_jbytes", types=[FDPType.VEC_I8, FDPType.I32]
        ),
        ("consumeShorts", 1): FDPMeta(
            method="produce_jshorts",
            types=[FDPType.VEC_I16, FDPType.I32],
        ),
        ("consumeInts", 1): FDPMeta(
            method="produce_jints", types=[FDPType.VEC_I32, FDPType.I32]
        ),
        ("consumeLongs", 1): FDPMeta(
            method="produce_jlongs",
            types=[FDPType.VEC_I64, FDPType.I32],
        ),
        ("consumeRemainingAsBytes", 0): FDPMeta(
            method="produce_remaining_as_jbytes",
            types=[
                FDPType.VEC_I8,
            ],
        ),
        ("consumeAsciiString", 1): FDPMeta(
            method="produce_ascii_string",
            types=[FDPType.STRING, FDPType.I32],
        ),
        ("consumeRemainingAsAsciiString", 0): FDPMeta(
            method="produce_remaining_as_ascii_string",
            types=[
                FDPType.STRING,
            ],
        ),
        ("consumeString", 1): FDPMeta(
            method="produce_jstring",
            types=[FDPType.STRING, FDPType.I32],
        ),
        ("consumeRemainingAsString", 0): FDPMeta(
            method="produce_remaining_as_jstring",
            types=[
                FDPType.STRING,
            ],
        ),
        ("remainingBytes", 0): FDPMeta(
            method="mark_remaining_bytes",
            types=[
                FDPType.USIZE,
            ],
        ),
        ("pickValue", 1): FDPMeta(
            method="produce_picked_value_index_in_jarray",
            types=[FDPType.USIZE, FDPType.USIZE],
        ),
        ("pickValues", 1): FDPMeta(
            method="produce_picked_value_indexes_in_jarray",
            types=[FDPType.VEC_USIZE, FDPType.USIZE],
        ),
    }

    def __init__(self):
        self._logger = logging.getLogger("FDPParser")

    async def parse(self, text: str) -> dict:
        try:
            jsons = re.findall(r"```json\n(.*?)```", text, re.DOTALL)
            if len(jsons) == 0:
                raise LLMParseException(
                    "You didn't include ```json\n``` in your answer. Please answer again with json."
                )
            if len(jsons) > 1:
                raise LLMParseException(
                    "You include ```json\n``` more than one. Please answer again with only one json."
                )

            try:
                root = pyjson5.loads(str(jsons[0]))
            except Exception as e:
                self._logger.info(f"Collected Json Format: {jsons[0]}")
                raise LLMParseException(
                    f"Failed to load json using pyjson5. Please try again. Below is failure message\n{e}"
                )

            invalid_elements: list[str] = []
            for x in root:
                if "method" not in x or "args" not in x or "value" not in x:
                    invalid_elements.append(
                        f"""There is missing key in {x} ("method", "args", "value" MUST be included)"""
                    )
                type_message: str = ""
                if not isinstance(x["method"], str):
                    type_message += "The value of method should be str"
                if not isinstance(x["args"], list):
                    if len(type_message) > 0:
                        type_message += ", "
                    type_message += "The value of args should be list"
                if len(type_message) > 0:
                    invalid_elements.append(
                        f"There is type error in {x}: {type_message}"
                    )

            if len(invalid_elements) > 0:
                self._logger.info(f"Loaded Json: {root}")
                raise LLMParseException(
                    f"Below is an invalid items in json format. You MUST specify \"method\", \"args\", \"value\" all for each\n{"\n".join([str(x) for x in invalid_elements])}"
                )

            invalid_elements: list[dict] = [
                x for x in root if (x["method"], len(x["args"])) not in FDPParser.table
            ]
            if len(invalid_elements) > 0:
                self._logger.info(f"Loaded Json: {root}")
                raise LLMParseException(
                    f"The following is a list of methods that don't seem to be provided by FuzzedDataProvider. Please double-check, and if there are any errors, delete them. If there are any spelling errors or incorrect argument counts, please correct them\n{"\n".join([str(x) for x in invalid_elements])}"
                )

            # Check invalid use
            for x in root:
                if (
                    x["method"] == "consumeBytes"
                    or x["method"] == "consumeInts"
                    or x["method"] == "consumeLongs"
                    or x["method"] == "consumeAsciiString"
                    or x["method"] == "consumeString"
                ):
                    if len(x["value"]) != int(x["args"][0]):
                        raise LLMParseException(
                            f'{x["method"]}\'s "value" length should be same as its first argument. Please fix json consider this'
                        )

            def put(type: FDPType, value: Any) -> str:
                if isinstance(value, str):
                    if type == FDPType.VEC_I8:
                        int_list: list[int] = [ord(x) for x in value]
                        value = f"bytes([{",".join(str(x) for x in int_list)}])"
                    else:
                        int_list: list[int] = [ord(x) for x in value]
                        value: str = (
                            f'reduce(lambda y, x: y + chr(x), {str(int_list)}, "")'
                        )
                return str(value)

            script: str = """
from functools import reduce
import base64
import libfdp
encoder = libfdp.JazzerFdpEncoder()
"""
            for x in root:
                meta: FDPMeta = FDPParser.table[(x["method"], len(x["args"]))]
                call: str = f"encoder.{meta.method}({put(meta.types[0], x["value"])}"
                for idx, arg in enumerate(x["args"]):
                    call += f",{put(meta.types[idx + 1], arg)}"
                call += ")"
                script += f"{call}\n"
            script += 'print(base64.b64encode(encoder.finalize()).decode("utf-8"))'
            script = script.strip()
            blob = b""
            with tempfile.NamedTemporaryFile(dir=Setting().tmp_dir, mode="wt") as f:
                f.write(script)
                f.flush()

                cmd = ["timeout", "-s", "SIGKILL", "10", sys.executable, f.name]
                p = await asyncio.create_subprocess_exec(
                    *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                try:
                    returncode, stdout, stderr = await async_process_run_and_exit(p, 10)
                except TimeoutError:
                    raise LLMParseException(
                        "Timeout happenes when run your script. Please do not include any logic that may cause timeout."
                    )
                if returncode != 0:
                    self._logger.info(f"script:\n{script}")
                    raise RuntimeError(
                        f"Failed to run python script (Below is an error message):\n{stderr.decode("utf-8")}"
                    )
                blob = stdout.decode("utf-8")

            blob: bytes = base64.b64decode(blob)
            result: dict = {"blob": blob, "script": str(root)}
            self._logger.info(f"Parse Succeed:\n{blob}")
            self._logger.debug(f"Script: {script}")
            return [result]
        except Exception as e:
            raise e


class FDPSeedGenerator(SeedGenerator):
    def __init__(self):
        self._logger = logging.getLogger("FDPSeedGenerator")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        feedback: str = "",
        prev: Optional[BlobGeneratorResult] = None,
    ) -> BlobGeneratorResult:
        script: str = prev.script if isinstance(prev, BlobGeneratorResult) else ""
        harness_path: str = CP().get_harness_path(harness_id)
        content: str = f"<PREVIOUS>\n{script}\n\n" if len(script) > 0 else ""
        content += f"<FEEDBACK>\n{feedback}\n\n" if len(feedback) > 0 else ""
        content += f"<POINT>\n{point}\n\n<CODE>\n{code}\n"
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""Your goal is to manipulate the FuzzedDataProvider, the first parameter of the {CP().target_method(harness_id)} method, to reach the code block labeled <POINT>.
To help you achieve this goal, I will provide you with the following information.
- CODE: The part of code you should analyze.
{"- PREVIOUS: Previous result" if len(script) > 0 else ""}
{"- FEEDBACK: Extra information learned from previous failure" if len(feedback) > 0 else ""}
FuzzedDataProvider is a class that stores values and provides them in the desired format through its method.

You need to understand the order in which the FuzzedDataProvider's methods are called when the program is executed, and then determine what values should be returned for each call to generate the input that reaches the desired location.
To achieve this goal, first think about how to analyze the code, then analyze the code according to the analysis steps. Finally, include the JSON format below. Make sure to write it in the order of method calls.
The order of method calls should consider loops, for example if method call is in the loop, then you should analyze how many times that method call executed, and include all calls in the list.
method should be the method of FuzzedDataProvider. Do not include not related methods.
And do not include below FuzzedDataProvider method.
- remainingBytes

args is list which indicates values that are used to invoke the method in the code. let it empty if no args are used.
In case of type, only use "" for string or bytes, otherwise just put the value in this json.
In case of bytes, please express them as python `bytes` style without prefix 'b'.
```json
[
   {{ "method": "FuzzedDataProvider method name", "args": [], "value": "value to be returned by method call"}}
  ...
]
```"""
            ),
            HumanMessage(content=content),
        ]
        result: BlobGeneratorResult = await BlobGenerator(
            SeedEvaluator(DebuggerVerifier(JDB()))
        ).generate2(path, harness_id, harness_path, messages, FDPParser(), model_names)
        self._logger.info(
            f"Generated [model={result.model_name}, score={result.eval.score}]"
        )
        return result


class PoVParser(metaclass=Singleton):
    sentinels: list[Sanitizer] = Field(default_factory=list)

    def __init__(self):
        self._lock = asyncio.Lock()
        self._script_file = Setting().tmp_dir / "tmp-pov-script.py"
        self._sentinel_file = Setting().tmp_dir / "tmp-pov-setinel"
        self._output_file = Setting().tmp_dir / "tmp-pov-output.bin"

    @async_safe("_lock")
    async def parse(self, text: str) -> list[dict]:
        scripts: list[str] = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
        result: list[dict] = []
        for script in scripts:
            if self.sentinels:
                result += [
                    {"blob": await self._run(script, sentinel), "script": script}
                    for sentinel in self.sentinels
                ]
            else:
                result.append({"blob": await self._run(script), "script": script})
        return result

    async def _run(self, script: str, value: Union[str | bytes] = "") -> bytes:
        async with aiofiles.open(self._script_file, "w") as f:
            await f.write(script)
            await f.flush()

        async with aiofiles.open(self._sentinel_file, "wb") as f:
            if isinstance(value, str):
                if len(value) > 0:
                    await f.write(value.encode("utf-8"))
                    await f.flush()
            else:
                await f.write(value)

        cmd: list[str] = [
            "timeout",
            "-s",
            "SIGKILL",
            "10",
            sys.executable,
            str(self._script_file),
            *([str(self._sentinel_file)] if value else []),
            str(self._output_file),
        ]
        p = await asyncio.create_subprocess_exec(*cmd)
        try:
            await async_process_run_and_exit(p, 10)
        except TimeoutError:
            raise LLMParseException(
                "Timeout happenes when run your script. Please do not include any logic that may cause timeout."
            )
        blob: bytes = b""
        async with aiofiles.open(self._output_file, mode="rb") as f:
            blob: bytes = await f.read()
        return blob


class PoVParser2(metaclass=Singleton):
    def __init__(self):
        self._lock = asyncio.Lock()
        self._script_file = Setting().tmp_dir / "tmp-pov2-script.py"
        self._sentinel_file = Setting().tmp_dir / "tmp-pov2-setinel"
        self._output_file = Setting().tmp_dir / "tmp-pov2-output.bin"

    @async_safe("_lock")
    async def parse(self, text: str) -> list[dict]:
        scripts: list[str] = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
        result: list[dict] = [
            {"blob": await self._run(script), "script": script} for script in scripts
        ]
        return result

    async def _run(self, script: str) -> bytes:
        async with aiofiles.open(self._script_file, "w") as f:
            await f.write(script)
            await f.flush()

        cmd: list[str] = [
            "timeout",
            "-s",
            "SIGKILL",
            "10",
            sys.executable,
            str(self._script_file),
            str(self._output_file),
        ]
        p = await asyncio.create_subprocess_exec(*cmd)
        try:
            await async_process_run_and_exit(p, 10)
        except TimeoutError:
            raise LLMParseException(
                "Timeout happenes when run your script. Please do not include any logic that may cause timeout."
            )
        blob: bytes = b""
        async with aiofiles.open(self._output_file, mode="rb") as f:
            blob: bytes = await f.read()
        return blob


class PoVGenerator(ABC):
    @abstractmethod
    def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        prev: BlobGeneratorResult,
        sanitizer: Sanitizer,
    ) -> BlobGeneratorResult:
        pass


class BytePoVGenerator(PoVGenerator):
    def __init__(self):
        self._logger = logging.getLogger("BytePoVGenerator")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        prev: BlobGeneratorResult,
        sanitizer: Sanitizer,
    ) -> BlobGeneratorResult:
        harness_path: str = CP().get_harness_path(harness_id)
        system_prompt, parser = self._system_prompt(sanitizer)
        messages: list[BaseMessage] = [
            system_prompt,
            HumanMessage(
                f"""<BLOB>
    {prev.blob}

    <POINT>
    {point}

    <SCRIPT>
    {prev.script}

    <CODE>
    {code}
    """
            ),
        ]
        result: BlobGeneratorResult = await BlobGenerator(
            PoVEvaluator(DebuggerVerifier(JDB()))
        ).generate2(
            path,
            harness_id,
            harness_path,
            messages,
            parser,
            model_names,
        )
        self._logger.info(
            f"Generated [model={result.model_name}, score={result.eval.score}"
        )
        return result

    def _system_prompt(
        self, sanitizer: Sanitizer
    ) -> tuple[SystemMessage, BaseOutputParser]:
        if sanitizer.name == "sink-FilePathTraversal":
            return (
                SystemMessage(
                    content="""You MUST write python script that generates blob that can trigger path traversal vulnerability in the given code.
Blob is passed as the first argument of fuzzTestOneInput function in the given code.
The python script MUST uses sys.argv[1].
sys.argv[1] is to value that a file path that generated blob stored into.
To trigger path traversal vulnerability, basically you should make the program access "../jazzer-traversal".
But if you find "jazzer.file_path_traversal_target" property is set while program is executing, then you should make the program access the value of the property.
You will get information about CODE, TYPE, POINT, BLOB, SCRIPT.
You MUST analyze CODE and TYPE to generate python script correctly.
POINT is the code part that malicious input should be injected.
BLOB is the value that reaches to the POINT.
SCRIPT is the python script that generates the BLOB.
Each information is given under the label which has a form like this: <each information name>"""
                ),
                PoVParser2(),
            )
        elif sanitizer.name == "sink-ServerSideRequestForgery":
            return (
                SystemMessage(
                    content="""You MUST write python script that generates blob that can trigger server side request forgery in the given code.
Blob is passed as the first argument of fuzzTestOneInput function in the given code.
The python script MUST uses sys.argv[1].
sys.argv[1] is to value that a file path that generated blob stored into.
To trigger server side request forgery vulnerability, basically you should make the program connect to "jazzer.example.com".
You will get information about CODE, TYPE, POINT, BLOB, SCRIPT.
You MUST analyze CODE and TYPE to generate python script correctly.
POINT is the code part that malicious input should be injected.
BLOB is the value that reaches to the POINT.
SCRIPT is the python script that generates the BLOB.
Each information is given under the label which has a form like this: <each information name>"""
                ),
                PoVParser2(),
            )
        elif sanitizer.name == "sink-BigDecimal":
            return (
                SystemMessage(
                    content="""You MUST write python script that generates blob that make system unstable by assigning big decimal value to cause oom or timeout.
Blob is passed as the first argument of fuzzTestOneInput function in the given code.
The python script MUST uses sys.argv[1].
sys.argv[1] is to value that a file path that generated blob stored into.
To make system unstable, basically you should make the program get decimal value as big as possible .
You will get information about CODE, TYPE, POINT, BLOB, SCRIPT.
You MUST analyze CODE and TYPE to generate python script correctly.
POINT is the code part that malicious input should be injected.
BLOB is the value that reaches to the POINT.
SCRIPT is the python script that generates the BLOB.
Each information is given under the label which has a form like this: <each information name>"""
                ),
                PoVParser2(),
            )
        else:
            parser = PoVParser()
            parser.sentinels = sanitizer.sentinel
            return (
                SystemMessage(
                    content="""You MUST write python script that generates blob that can trigger vulnerability in the given code.
Blob is passed as the first argument of fuzzTestOneInput function in the given code.
The python script MUST uses sys.argv[1], sys.argv[2].
sys.argv[1] is a file path that has a value to be injected malicious code part to trigger vulnerability. Read this file as bytes and use that value.
sys.argv[2] is to value that a file path that generated blob stored into.
You will get information about CODE, TYPE, POINT, BLOB, SCRIPT.
You MUST analyze CODE and TYPE to generate python script correctly.
POINT is the code part that malicious input should be injected.
BLOB is the value that reaches to the POINT.
SCRIPT is the python script that generates the BLOB.
Each information is given under the label which has a form like this: <each information name>"""
                ),
                parser,
            )


class FDPPoVGenerator(PoVGenerator):
    def __init__(self):
        self._logger = logging.getLogger("FDPPoVGenerator")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        prev: BlobGeneratorResult,
        sanitizer: Sanitizer,
    ) -> BlobGeneratorResult:
        template: str = prev.script
        harness_path: str = CP().get_harness_path(harness_id)

        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""Your goal is to manipulate the FuzzedDataProvider, the first parameter of the {CP().target_method(harness_id)} method, to trigger the vulnerability in the given code.
Especially, you can trigger vulnerability by injecting malicious input to the code part under <POINT> label.
To help you achieve this goal, I will provide you with the following information.
- CODE: The part of code you should analyze.
- TEMPLATE: The output template you should answer.
{"- SENTINEL: The value to prove exploitability." if len(sanitizer.sentinel) > 0 else ""}
FuzzedDataProvider is a class that stores values and provides them in the desired format through its method.
<TEMPLATE> is the json format like below.
```json
[
   {{ "method": "FuzzedDataProvider method name", "args": [], "value": "value to be returned by method call"}}
  ...
]
args is list which indicates values that are used to invoke the method in the code. let it empty if no args are used.
In case of type, only use "" for string or bytes, otherwise just put the value in this json.
In case of bytes, please express them as python `bytes` style without prefix 'b'.

I'll make input from this <TEMPLATE> by my own method.
Current template guarantees the input from <TEMPLATE> can reach <POINT>,
so what you MUST do is to modify <TEMPLATE> to trigger vulnerability, especially "value" in the json is where you have to modify.
{"""The bug oracle is hooking functions in <POINT> and checks an related argument value is the value under <SENTINEL>.
So, please replace a part of <TEMPLATE> as <SENTINEL> value so that bug oracle can catch it.""" if len(sanitizer.sentinel) > 0 else ""}
"""
            ),
            HumanMessage(
                f"""<TEMPLATE>
{template}
{f"""
<SENTINEL>
{sanitizer.sentinel[0]}""" if len(sanitizer.sentinel) > 0 else ""}

<POINT>
{point}

<CODE>
{code}"""
            ),
        ]
        result: BlobGeneratorResult = await BlobGenerator(
            PoVEvaluator(DebuggerVerifier(JDB()))
        ).generate2(
            path,
            harness_id,
            harness_path,
            messages,
            FDPParser(),
            model_names,
        )
        self._logger.info(
            f"Generated [model={result.model_name}, score={result.eval.score}"
        )
        return result


class ByteSeedGeneratorNoFeedback(SeedGenerator):
    def __init__(self):
        self._logger = logging.getLogger("ByteSeedGeneratorNoFeedback")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        feedback: str = "",
        prev: Optional[BlobGeneratorResult] = None,
    ) -> list[BlobGeneratorResult]:
        harness_path: str = CP().get_harness_path(harness_id)
        fuzzer_entry = CP().target_method(harness_id)
        content = f"<POINT>\n{point}\n\n<CODE>\n{code}\n"
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""You MUST write a python script that generates input values for the first parameter of the {fuzzer_entry} method, ensuring that this value can reach a specific location.
A Python script MUST uses sys.argv[1].
sys.argv[1] is the path of the file where the generated data blob will be stored.
You will get information about CODE and POINT.
You MUST analyze CODE to generate python script correctly.
POINT is the code part that should be reached by the generated blob.
There some tips you may mistake when inferring blob:
- Endianess
"""
            ),
            HumanMessage(content=content),
        ]

        results: list[dict] = [
            await BlobGenerator(SeedEvaluator(GDBVerifier())).generate(
                path,
                harness_id,
                harness_path,
                messages,
                PythonParser(),
                model_name,
            )
            for model_name in model_names
        ]
        self._logger.info("Generated:")
        [
            self._logger.info(
                f"- {x.model_name}: [score={x.eval.score}, blob={x.blob}]"
            )
            for x in results
        ]
        return max(results, key=lambda x: x.eval.score)


class BytePoVGeneratorNoSentinel(PoVGenerator):
    def __init__(self):
        self._logger = logging.getLogger("BytePoVGeneratorNoSentinel")

    async def generate(
        self,
        code: str,
        harness_id: str,
        model_names: list[str],
        path: list[CodePoint],
        point: str,
        prev: BlobGeneratorResult,
        sanitizer: Sanitizer,
    ) -> BlobGeneratorResult:
        harness_path: str = CP().get_harness_path(harness_id)
        messages: list[BaseMessage] = [
            SystemMessage(
                content=f"""You MUST write python script that generates blob that can trigger vulnerability in the given code.
Blob is passed as the first argument of {CP().target_method(harness_id)} function in the given code.
The python script MUST uses sys.argv[1].
sys.argv[1] is to value that a file path that generated blob stored into.
You will get information about CODE, TYPE, POINT, BLOB, SCRIPT.
You MUST analyze CODE and TYPE to generate python script correctly.
TYPE is the sanitizer you should focus on.
POINT is the code part that malicious input should be injected.
BLOB is the value that reaches to the POINT.
SCRIPT is the python script that generates the BLOB.
Each information is given under the label which has a form like this: <each information name>
You MUST include python script in your answer. Put python script in ```python\\n``` format.
"""
            ),
            HumanMessage(
                f"""<BLOB>
    {prev.blob}

    <POINT>
    {point}

    <SCRIPT>
    {prev.script}

    <CODE>
    {code}
    """
            ),
        ]

        parser = PoVParser()
        parser.sentinels = sanitizer.sentinel
        results: list[dict] = [
            await BlobGenerator(PoVEvaluator(GDBVerifier(), use_jazzer=False)).generate(
                path,
                harness_id,
                harness_path,
                messages,
                parser,
                model_name,
            )
            for model_name in model_names
        ]
        self._logger.info("Generated:")
        [
            self._logger.info(
                f"- {x.model_name}: [score={x.eval.score}, blob={x.blob}, crash={x.eval.crash}]"
            )
            for x in results
        ]
        return max(results, key=lambda x: x.eval.score)


class BlobGenFactory(ABC):
    @abstractmethod
    def create_seed_generator(self):
        pass

    @abstractmethod
    def create_pov_generator(self):
        pass


class ByteBlobGenFactory(BlobGenFactory):
    def create_seed_generator(self) -> SeedGenerator:
        return ByteSeedGenerator()

    def create_pov_generator(self) -> PoVGenerator:
        return BytePoVGenerator()


class FDPBlobGenFactory(BlobGenFactory):
    def create_seed_generator(self) -> SeedGenerator:
        return FDPSeedGenerator()

    def create_pov_generator(self) -> PoVGenerator:
        return FDPPoVGenerator()


class OneTimeBlobGenFactory(BlobGenFactory):
    def create_seed_generator(self) -> SeedGenerator:
        return ByteSeedGeneratorNoFeedback()

    def create_pov_generator(self) -> PoVGenerator:
        return BytePoVGeneratorNoSentinel()


def create_blobgen_factory(
    harness_type: str, with_sentinel: bool = True, with_feedback: bool = True
) -> BlobGenFactory:
    if not with_sentinel and not with_feedback:
        return OneTimeBlobGenFactory()
    if harness_type == "byte":
        return ByteBlobGenFactory()
    elif harness_type == "fdp":
        return FDPBlobGenFactory()
    raise RuntimeError(f"Unsupported harness_type: {harness_type}")
