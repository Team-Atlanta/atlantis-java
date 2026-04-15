import asyncio
import hashlib
import logging
import pickle
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TypeVar

import aiosqlite
from langchain_core.caches import BaseCache
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.messages.ai import AIMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.output_parsers.base import BaseOutputParser
from langchain_core.outputs import Generation
from langchain_core.outputs.chat_generation import ChatGeneration
from langchain_core.outputs.llm_result import LLMResult
from langchain_core.runnables import Runnable
from langchain_core.runnables.base import RunnableSequence
from openai import APIStatusError
from redis.asyncio import Redis
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

from vuli.chatlog import ChatLog
from vuli.common.decorators import SEVERITY, async_lock, async_safe
from vuli.common.singleton import Singleton
from vuli.struct import LLMParseException, LLMRetriable

T = TypeVar("T")


class MultiCache(BaseCache):

    def __init__(self, handlers: list[BaseCache]):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._lock = asyncio.Lock()
        handlers = [handler for handler in handlers if isinstance(handler, BaseCache)]
        self._handlers = handlers
        self._logger.info(
            f"LLM Multi-Cache is initialized [handlers={",".join([handler.__class__.__name__ for handler in self._handlers])}]"
        )

    @async_lock("_lock")
    async def aclear(self):
        @async_safe(None, SEVERITY.ERROR, "MultiCache")
        async def safe_clear(handler) -> None:
            await handler.clear()

        [await safe_clear(handler) for handler in self._handlers]

    @async_lock("_lock")
    async def alookup(
        self, prompt: str, llm_string: str
    ) -> Optional[Sequence[Generation]]:
        @async_safe(None, SEVERITY.ERROR, "MultiCache")
        async def safe_lookup(handler, prompt: str, llm_string: str) -> None:
            return await handler.alookup(prompt, llm_string)

        for handler in self._handlers:
            result: Optional[Sequence[Generation]] = await safe_lookup(
                handler, prompt, llm_string
            )
            if result is not None:
                return result
        return None

    @async_lock("_lock")
    async def aupdate(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ) -> None:
        @async_safe(None, SEVERITY.ERROR, "MultiCache")
        async def safe_update(
            handler, prompt: str, llm_string: str, return_val: Sequence[Generation]
        ) -> None:
            await handler.aupdate(prompt, llm_string, return_val)

        [
            await safe_update(handler, prompt, llm_string, return_val)
            for handler in self._handlers
        ]

    def clear(self):
        [handler.clear() for handler in self._handlers]

    def lookup(self, prompt: str, llm_string: str) -> Optional[Sequence[Generation]]:
        for handler in self._handlers:
            result: Optional[Sequence[Generation]] = handler.lookup(prompt, llm_string)
            if result is not None:
                return result
        return None

    def update(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ) -> None:
        [handler.update(prompt, llm_string, return_val) for handler in self._handlers]


class DBCache(BaseCache):
    def __init__(self, path: Path):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._path = path
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    key TEXT PRIMARY KEY,
                    data BLOB,
                    last_accessed TIMESTAMP
                )
                """
            )
            conn.commit()

    async def aclear():
        pass

    async def alookup(
        self, prompt: str, llm_string: str
    ) -> Optional[Sequence[Generation]]:
        key: str = self._key(prompt, llm_string)
        result: Optional[Sequence[Generation]] = await self._load(key)
        if result is None:
            self._logger.info(f"DB Model Cache Miss [key={key}]")
            return result
        self._logger.info(f"DB Model Cache Hit [key={key}]")

        if (
            not isinstance(result, Sequence)
            or len(result) == 0
            or not isinstance(result[0], ChatGeneration)
        ):
            self._logger.info("DB Model Cache Lookup Error [Invalid format]")
            return None

        for generation in result:
            generation.message.response_metadata["from_cache"] = True
        return result

    async def aupdate(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ):
        try:
            key: str = self._key(prompt, llm_string)
            await self._save(key, return_val)
            self._logger.info(f"DB Model Cache Update [key={key}]")
        except Exception as e:
            self._logger.info(
                f"DB Model Cache Update Error [exc={e.__class__.__name__}: {e}]"
            )

    def clear(self):
        pass

    def lookup(self, prompt: str, llm_string: str) -> Optional[Sequence[Generation]]:
        return None

    def update(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ) -> None:
        pass

    @async_safe(None, SEVERITY.ERROR, "DBCache")
    async def _load(self, key):
        async with aiosqlite.connect(str(self._path)) as conn:
            cursor = await conn.execute(
                "SELECT data, last_accessed FROM objects WHERE key = ?",
                (key,),
            )
            row = await cursor.fetchone()

            if row:
                serialized_data, _ = row
                obj = pickle.loads(serialized_data)

                await conn.execute(
                    "UPDATE objects SET last_accessed = ? WHERE key = ?",
                    (self._time(), key),
                )
                return obj
        return None

    @async_safe(None, SEVERITY.ERROR, "DBCache")
    async def _save(self, key, obj):
        serialized_data = pickle.dumps(obj)
        last_accessed = self._time()
        async with aiosqlite.connect(str(self._path)) as conn:
            await conn.execute(
                """
                INSERT INTO objects (key, data, last_accessed)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    data=excluded.data,
                    last_accessed=excluded.last_accessed
                """,
                (key, serialized_data, last_accessed),
            )
            await conn.commit()

    def _key(self, prompt: str, llm_string: str) -> str:
        return hashlib.sha256(f"{prompt}{llm_string}".encode()).hexdigest()

    def _time(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class RedisCache(BaseCache):

    def __init__(self, url: str):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._redis = Redis.from_url(url)

    async def aclear(self) -> None:
        return

    async def alookup(
        self, prompt: str, llm_string: str
    ) -> Optional[Sequence[Generation]]:
        try:
            key: str = self._key(prompt, llm_string)
            result: Optional[bytes] = await self._redis.get(key)
            if result is None:
                self._logger.info(f"Redis Model Cache Miss [key={key}]")
                return

            self._logger.info(f"Redis Model Cache Hit [key={key}]")
            result: Sequence[Generation] = pickle.loads(result)
            if (
                not isinstance(result, Sequence)
                or len(result) == 0
                or not isinstance(result[0], ChatGeneration)
            ):
                self._logger.info("Redis Model Cache Lookup Error [invalid format]")
                await self._redis.delete(key)
                return None

            for generation in result:
                generation.message.response_metadata["from_cache"] = True

            return result
        except Exception as e:
            self._logger.warning(
                f"Redis Model Cache Lookup Error [exc={e.__class__.__name__}: {e}]"
            )
            return None

    async def aupdate(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ):
        try:
            key: str = self._key(prompt, llm_string)
            result: bool = await self._redis.set(
                self._key(prompt, llm_string), pickle.dumps(return_val)
            )
            if result is True:
                self._logger.info(f"Redis Model Cache Update [key={key}]")
            else:
                self._logger.info("Redis Model Cache Update Fail")
        except Exception as e:
            self._logger.info(
                f"Redis Model Cache Update Fail [key={key}, exc={e.__class__.__name__}:{e}]"
            )

    def clear(self):
        pass

    def lookup(self, prompt: str, llm_string: str) -> Optional[Sequence[Generation]]:
        return None

    def update(
        self, prompt: str, llm_string: str, return_val: Sequence[Generation]
    ) -> None:
        pass

    def _key(self, prompt: str, llm_string: str) -> str:
        return (
            f"llmpocgen-{hashlib.sha256(f"{prompt}{llm_string}".encode()).hexdigest()}"
        )


class UsageCallBack(BaseCallbackHandler):
    def __init__(self, cost_function: Callable):
        self._cost: float = 0.0
        self._saved: float = 0.0
        self._cost_function: Callable = cost_function

    def get_usage(self) -> tuple[float, float]:
        return (self._cost, self._saved)

    def reset(self) -> None:
        self._cost: float = 0.0
        self._saved: float = 0.0

    def on_llm_end(self, response: LLMResult, **kwargs) -> Any:
        # At least, gpt-4.1, even if there are multiple responses, the token
        # count for all responses is added together and recorded in the
        # metadata of each response. Therefore, only need to use one.
        if len(response.generations) > 0:
            if len(response.generations[0]) > 0:
                message: BaseMessage = response.generations[0][0].message
                prompt_tokens: int = message.usage_metadata["input_tokens"]
                completion_tokens: int = message.usage_metadata["output_tokens"]
                cost: float = self._cost_function(prompt_tokens, completion_tokens)
                self._cost += cost
                if message.response_metadata.get("from_cache", False):
                    self._saved += cost

        # Delete metadata `from_cache` that is created by this tool
        for generations in response.generations:
            for generation in generations:
                if "from_cache" in generation.message.response_metadata:
                    del generation.message.response_metadata["from_cache"]


@dataclass
class ModelMetadata:
    model: BaseChatModel
    usage: UsageCallBack


class ModelManager(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("ModelManager")
        self._cache: Optional[BaseCache] = None
        self._lock = asyncio.Lock()
        self._models: dict = {}
        self._max_retries: int = 0

    @async_lock("_lock")
    async def add_model(
        self,
        cost_function: Callable,
        model_name: str,
        model: BaseChatModel,
    ) -> None:
        self._models[model_name] = ModelMetadata(model, UsageCallBack(cost_function))
        self._logger.info(f"Model is added (Name:{model_name})")

    def get_all_model_names(self) -> list[str]:
        return sorted(list(self._models.keys()))

    def resolve_model(self, preferred: str) -> str:
        """Resolve a preferred model name against available models.

        Returns the preferred model if available, otherwise the first
        registered model. Raises RuntimeError if no models are registered.
        """
        if preferred in self._models:
            return preferred
        if self._models:
            fallback = next(iter(self._models))
            self._logger.warning(f"Model '{preferred}' not available, falling back to '{fallback}'")
            return fallback
        raise RuntimeError(f"No models registered (requested '{preferred}')")

    def resolve_models(self, preferences: list[str]) -> list[str]:
        """Filter a preference list against available models.

        Returns the subset of preferred models that are registered, preserving
        order. If none match, returns all registered models.
        """
        resolved = [m for m in preferences if m in self._models]
        if resolved:
            return resolved
        # None of the preferred models are available — return all available
        return list(self._models.keys())

    def get_total_usage(self) -> tuple[float, float]:
        total_cost: float = 0.0
        total_saved: float = 0.0
        for metadata in self._models.values():
            cost, saved = metadata.usage.get_usage()
            total_cost += cost
            total_saved += saved
        return (total_cost, total_saved)

    def print_total_usage(self) -> str:
        result: str = ""
        for name, metadata in self._models.items():
            cost, saved = metadata.usage.get_usage()
            result += f"{name}: (cost: {cost}, saved: {saved})\n"
        if len(result) > 0 and result[-1] == "\n":
            result = result[:-1]
        return result

    @async_lock("_lock")
    async def clear(self) -> None:
        self._cache = None
        self._models = {}

    @async_lock("_lock")
    async def reset_usage(self) -> None:
        for metadata in self._models.values():
            metadata.usage.reset()

    @async_lock("_lock")
    async def set_cache(self, cache: BaseCache) -> None:
        self._cache = cache

    @async_lock("_lock")
    async def set_max_retries(self, max_retries: int) -> None:
        self._max_retries: int = max_retries
        self._logger.info(f"Retry limit is set to {max_retries}")

    # @async_lock("_lock")
    async def invoke_atomic(
        self,
        messages: list[BaseMessage],
        model_name: str,
        parser: Optional[RunnableSequence],
        agent: str = "",
    ) -> Any:
        """
        Raises: RuntimeError, LLMRetriable
        """
        if model_name not in self._models:
            raise RuntimeError(f"Model '{model_name}' is not registered")

        metadata: ModelMetadata = self._models[model_name]
        if self._cache:
            metadata.model.cache = self._cache

        try:
            message: BaseMessage = await self._invoke_atomic(
                metadata.model, messages, {"callbacks": [metadata.usage]}
            )
        except Exception as e:
            raise e

        if agent:
            ChatLog().log(agent, model_name, messages, message)

        try:
            _, result, _ = await self._retry_parse(
                metadata.model,
                parser,
                message.content,
                {"callbacks": [metadata.usage]},
                1,
                agent=agent,
            )
        except LLMRetriable as e:
            raise e
        except Exception:
            raise RuntimeError("LLM Output has unexpected format")
        return result

    @async_lock("_lock")
    async def invoke(
        self,
        messages: list[BaseMessage],
        model_name: str,
        parser: Optional[RunnableSequence],
        agent: str = "",
    ) -> Any:
        """
        Raises: RuntimeError, LLMParseException, LLMRetriable, RuntimeError
        """
        if model_name not in self._models:
            raise RuntimeError(f"Model '{model_name}' is not registered")

        metadata: ModelMetadata = self._models[model_name]
        if self._cache:
            metadata.model.cache = self._cache

        for i in range(0, self._max_retries + 1):
            try:
                [
                    self._logger.debug(f"LLM Input\n{message.pretty_repr()}")
                    for message in messages
                ]
                message: BaseMessage = await self._invoke(
                    metadata.model, messages, {"callbacks": [metadata.usage]}
                )
                self._logger.debug(f"LLM Response [{message.pretty_repr()}]")
                if agent:
                    ChatLog().log(agent, model_name, messages, message)
                _, result, _ = await self._retry_parse(
                    metadata.model,
                    parser,
                    message.content,
                    {"callbacks": [metadata.usage]},
                    self._max_retries,
                    agent=agent,
                )
                return result
            except LLMParseException as e:
                if i == self._max_retries:
                    raise e
            except Exception as e:
                self._logger.warning(
                    f"Skip Exception [case=while handling LLM answer, msg={e}]"
                )
        raise RuntimeError("Unexpected State")

    def _retry_case(e) -> bool:
        logging.getLogger("ModelManager").warning(
            f"Exception Raised From LLM: {e.__class__.__name__}: {e}"
        )
        if isinstance(e, APIStatusError):
            status_code: int = getattr(e, "status_code", 0)
            return status_code == 429 or status_code >= 500
        return True

    @retry(
        retry=retry_if_exception(_retry_case),
        wait=wait_fixed(60) + wait_random(0, 10),
        stop=stop_after_attempt(10),
    )
    async def _invoke(
        self, runnable: Runnable, messages: list[BaseMessage], config: dict = {}
    ) -> BaseMessage:
        self._logger.info(f"Waiting LLM [model={runnable.model_name}]")
        result: BaseMessage = await runnable.ainvoke(messages, config)
        self._logger.info(
            f"Succeed to get message from LLM [model={runnable.model_name}]"
        )
        return result

    async def _invoke_atomic(
        self, runnable: Runnable, messages: list[BaseMessage], config: dict = {}
    ) -> BaseMessage:
        """
        Raises: LLMRetriable, RuntimeError
        """
        try:
            self._logger.info(f"Waiting LLM [model={runnable.model_name}]")
            result: BaseMessage = await runnable.ainvoke(messages, config)
            self._logger.info(
                f"Succeed to get message from LLM [model={runnable.model_name}]"
            )
            return result
        except Exception as e:
            if isinstance(e, APIStatusError):
                status_code: int = getattr(e, "status_code", 0)
                if status_code == 429 or status_code >= 500:
                    raise LLMRetriable("")
            raise RuntimeError("Failed to get response from LLM")

    async def _retry_parse(
        self,
        runnable: Runnable,
        parser: BaseOutputParser[T],
        completion: str,
        config: dict = {},
        max_retries=1,
        agent: str = "",
    ):
        """
        Raises: LLMParseException, LLMRetriable, RuntimeException
        """
        retries = 0
        parse_content = completion
        messages: list[BaseMessage] = []
        while retries <= max_retries:
            try:
                return (parse_content, await parser.parse(parse_content), False)
            except LLMParseException as e:
                if retries == max_retries:
                    raise e
                else:
                    retries += 1
                    messages.append(AIMessage(content=parse_content))
                    messages.append(HumanMessage(content=str(e)))
                    message: BaseMessage = await self._invoke_atomic(
                        runnable, messages, config
                    )
                    if agent:
                        ChatLog().log(
                            agent, runnable.model_name, messages, message
                        )
                    parse_content = message.content
        raise LLMParseException("Failed to parse")
