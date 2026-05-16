import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.messages.ai import AIMessage
from langchain_core.output_parsers.base import BaseOutputParser
from langchain_core.outputs import ChatResult
from langchain_core.outputs.chat_generation import ChatGeneration
from langchain_openai import ChatOpenAI
from openai import APITimeoutError, AuthenticationError

from vuli.model_manager import DBCache, ModelManager, MultiCache
from vuli.struct import LLMParseException, LLMRetriable


@pytest.fixture(autouse=True)
def setup():
    asyncio.run(ModelManager().clear())
    asyncio.run(ModelManager().reset_usage())


class MockChatModel(BaseChatModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._counter: int = 0

    def _generate(self, messages: list[BaseMessage], *args, **kwargs) -> ChatResult:
        # NOTE: This is actual response from gpt-4o
        return ChatResult(
            generations=[
                ChatGeneration(
                    text=f"{str(self._counter)}",
                    message=AIMessage(
                        content="Euphoria.",
                        additional_kwargs={"refusal": None},
                        response_metadata={
                            "token_usage": {
                                "completion_tokens": 4,
                                "prompt_tokens": 13,
                                "total_tokens": 17,
                                "completion_tokens_details": {
                                    "accepted_prediction_tokens": 0,
                                    "audio_tokens": 0,
                                    "reasoning_tokens": 0,
                                    "rejected_prediction_tokens": 0,
                                },
                                "prompt_tokens_details": {
                                    "audio_tokens": 0,
                                    "cached_tokens": 0,
                                },
                            },
                            "model_name": "gpt-4o-2024-08-06",
                            "system_fingerprint": "fp_b7d65f1a5b",
                            "finish_reason": "stop",
                            "logprobs": None,
                        },
                        id="run-43603557-546f-4d78-9b3a-dd7f8755f8c7-0",
                        usage_metadata={
                            "input_tokens": 13,
                            "output_tokens": 4,
                            "total_tokens": 17,
                            "input_token_details": {
                                "audio": 0,
                                "cache_read": 0,
                            },
                            "output_token_details": {
                                "audio": 0,
                                "reasoning": 0,
                            },
                        },
                    ),
                )
            ]
        )

    @property
    def _llm_type(self) -> str:
        "mock"

    @property
    def model_name(self) -> str:
        "mock"


class SimpleParser(BaseOutputParser[str]):
    async def parse(self, text: str) -> str:
        return text


class MockParser(BaseOutputParser[str]):
    def __init__(self, success_cond: int):
        super().__init__()
        self._success_cond: int = success_cond
        self._counter: int = 0

    def reset(self) -> None:
        self._counter: int = 0

    async def parse(self, text: str) -> str:
        if self._counter >= self._success_cond:
            return str(self._counter)
        else:
            self._counter += 1
            raise LLMParseException()


@pytest.mark.asyncio
async def test_cache():
    """
    Test
        ModelManager should preserver info to calculate usage
    """
    t = tempfile.NamedTemporaryFile()
    manager = ModelManager()
    await manager.add_model(
        lambda input, output: input + output, "mock", MockChatModel()
    )
    await manager.reset_usage()
    await manager.set_cache(MultiCache([DBCache(Path(t.name))]))
    await manager.invoke([], "mock", SimpleParser())
    await manager.set_cache(MultiCache([DBCache(Path(t.name))]))
    await manager.invoke([], "mock", SimpleParser())
    cost, saved = manager.get_total_usage()
    assert cost == 34.0 and saved == 17.0


@pytest.mark.asyncio
async def test_cost():
    """
    Test
        Manager can return the cost of interaction
    """
    manager = ModelManager()
    await manager.add_model(
        lambda input, output: input + output, "mock", MockChatModel()
    )
    await manager.invoke([], "mock", SimpleParser())
    assert manager.get_total_usage() == (17.0, 0.0)


@pytest.mark.asyncio
async def test_used():
    manager = ModelManager()
    await manager.add_model(
        lambda input, output: input + output, "mock", MockChatModel()
    )
    await manager.set_max_retries(0)

    # When First Call Failed
    with pytest.raises(LLMParseException):
        await manager.invoke([], "mock", MockParser(10))
    assert manager.get_total_usage() == (17.0, 0.0)

    # When Retry Failed
    await manager.set_max_retries(3)
    await manager.reset_usage()
    with pytest.raises(LLMParseException):
        await manager.invoke([], "mock", MockParser(20))
    assert manager.get_total_usage() == (272.0, 0.0)

    # When Retry Succeed
    await manager.reset_usage()
    await manager.invoke([], "mock", MockParser(2))
    assert manager.get_total_usage() == (51.0, 0.0)


@pytest.mark.asyncio
async def test_get_all_model_names():
    manager = ModelManager()
    await manager.add_model(
        lambda input, output: input + output, "mock1", MockChatModel()
    )
    assert manager.get_all_model_names() == ["mock1"]

    await manager.add_model(
        lambda input, output: input + output * 2, "mock2", MockChatModel()
    )
    assert manager.get_all_model_names() == ["mock1", "mock2"]


@pytest.mark.asyncio
async def test_model_manager_invoke_no_model_name():
    with pytest.raises(RuntimeError):
        await ModelManager().invoke([], "", None)


@pytest.mark.asyncio
async def test_model_manager_invoke_llm_exception():
    await ModelManager().add_model(lambda x, y: x + y, "dummy", None)
    await ModelManager().set_max_retries(1)
    with patch.object(ModelManager, "_invoke") as p:

        def mock(*args, **kwargs) -> None:
            raise RuntimeError

        p.side_effect = mock
        with pytest.raises(RuntimeError):
            await ModelManager().invoke([], "dummy", None)
        assert p._mock_call_count == 2


@pytest.mark.asyncio
@patch("vuli.model_manager.MultiCache.aupdate")
@patch("vuli.model_manager.MultiCache.alookup")
async def test_cache_exception(p1, p2):
    """
    Cache should not be updated if exceptions happens
    (!This implemention depends on langchain framework)
    """
    await ModelManager().add_model(
        lambda input, output: 0,
        "mock",
        ChatOpenAI(api_key="mock", cache=MultiCache([]), model="mock"),
    )
    await ModelManager().set_max_retries(0)

    # This will cause AuthenticationError from BaseModel, which caught by
    # ModelManager and finally RuntimError will be raised.
    with pytest.raises(RuntimeError):
        await ModelManager().invoke([], "mock", None)

    # Lookup should be called
    p1.assert_called_once()
    # Update should not called
    p2._mock_call_count = 0


@pytest.mark.asyncio
async def test_invoke_non_register_model():
    model_name: str = "fake"
    assert model_name not in ModelManager().get_all_model_names()
    with pytest.raises(RuntimeError):
        await ModelManager().invoke_atomic([], model_name, None)


@pytest.mark.asyncio
async def test_invoke_unknown_name_with_other_registered():
    """Strict dispatch: unknown model raises even if others are registered."""
    await ModelManager().add_model(
        lambda input, output: input + output, "mock", MockChatModel()
    )
    with pytest.raises(RuntimeError):
        await ModelManager().invoke_atomic([], "fake", None)
    with pytest.raises(RuntimeError):
        await ModelManager().invoke([], "fake", None)


@pytest.mark.asyncio
async def test_resolve_model_fallback():
    await ModelManager().add_model(
        lambda input, output: input + output, "mock", MockChatModel()
    )
    assert ModelManager().resolve_model("mock") == "mock"
    assert ModelManager().resolve_model("missing") == "mock"


@pytest.mark.asyncio
async def test_resolve_models_preserves_preference_order():
    await ModelManager().add_model(
        lambda input, output: input + output, "a", MockChatModel()
    )
    await ModelManager().add_model(
        lambda input, output: input + output, "b", MockChatModel()
    )
    assert ModelManager().resolve_models(["b", "missing", "a"]) == ["b", "a"]
    # No preferences match → return all registered as fallback
    assert sorted(ModelManager().resolve_models(["x", "y"])) == ["a", "b"]


@pytest.mark.asyncio
@patch.object(ModelManager, "_invoke_atomic")
async def test_invoke_runtime_error_from__invoke_atomic(patch_1):
    async def mock_1(*args, **kwargs) -> None:
        raise RuntimeError

    patch_1.side_effect = mock_1
    model_name: str = "mock"
    await ModelManager().add_model(
        lambda input, output: input + output, model_name, MockChatModel()
    )
    with pytest.raises(RuntimeError):
        await ModelManager().invoke_atomic([], model_name, None)


@pytest.mark.asyncio
@patch.object(ModelManager, "_invoke_atomic")
async def test_invoke_llmretriable_from__invoke_atomic(patch_1):
    async def mock_1(*args, **kwargs) -> None:
        raise LLMRetriable

    patch_1.side_effect = mock_1
    model_name: str = "mock"
    await ModelManager().add_model(
        lambda input, output: input + output, model_name, MockChatModel()
    )
    with pytest.raises(LLMRetriable):
        await ModelManager().invoke_atomic([], model_name, None)


@pytest.mark.asyncio
@patch.object(ModelManager, "_retry_parse")
@patch.object(ModelManager, "_invoke_atomic")
async def test_invoke_runtime_error_from__retry_parse(patch_1, patch_2):
    async def mock_2(*args, **kwargs) -> None:
        raise RuntimeError

    patch_1.return_value = []
    patch_2.side_effect = mock_2
    model_name: str = "mock"
    await ModelManager().add_model(
        lambda input, output: input + output, model_name, MockChatModel()
    )
    with pytest.raises(RuntimeError):
        await ModelManager().invoke_atomic([], model_name, None)


@pytest.mark.asyncio
@patch.object(ModelManager, "_retry_parse")
@patch.object(ModelManager, "_invoke_atomic")
async def test_invoke_llmretriable_from__retry_parse(patch_1, patch_2):
    async def mock_2(*args, **kwargs) -> None:
        raise LLMRetriable

    patch_1.return_value = AIMessage(content="")
    patch_2.side_effect = mock_2
    model_name: str = "mock"
    await ModelManager().add_model(
        lambda input, output: input + output, model_name, MockChatModel()
    )
    with pytest.raises(LLMRetriable):
        await ModelManager().invoke_atomic([], model_name, None)


@pytest.mark.asyncio
@patch("langchain_core.language_models.chat_models.BaseChatModel.ainvoke")
async def test__invoke_atomic_any_exception(patch_1):
    async def mock_1(*args, **kwargs) -> None:
        raise RuntimeError

    patch_1.side_effect = mock_1
    patch_1.raises
    with pytest.raises(RuntimeError):
        await ModelManager()._invoke_atomic(MockChatModel(), [])


@pytest.mark.asyncio
@patch("langchain_core.language_models.chat_models.BaseChatModel.ainvoke")
async def test__invoke_atomic_timeout_exception(patch_1):
    async def mock_1(*args, **kwargs) -> None:
        raise APITimeoutError

    patch_1.side_effect = mock_1
    with pytest.raises(RuntimeError):
        await ModelManager()._invoke_atomic(MockChatModel(), [])


@pytest.mark.asyncio
@patch("langchain_core.language_models.chat_models.BaseChatModel.ainvoke")
async def test__invoke_atomic_auth_exception(patch_1):
    async def mock_1(*args, **kwargs) -> None:
        raise AuthenticationError()

    patch_1.side_effect = mock_1
    with pytest.raises(RuntimeError):
        await ModelManager()._invoke_atomic(MockChatModel(), [])
