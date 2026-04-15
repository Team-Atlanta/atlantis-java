from abc import ABC, abstractmethod
from typing import Optional


class LLMModel(ABC):
    @abstractmethod
    def cost(self, input, output):
        pass

    @property
    @abstractmethod
    def name(self):
        pass


class Grok3(LLMModel):
    def cost(self, input, output):
        return input * 0.000003 + output * 0.000015

    @property
    def name(self):
        return "grok-3"


class Gemini25Pro(LLMModel):
    def cost(self, input, output):
        return (
            input * 0.00000125 + output * 0.00001
            if input < 200000
            else input * 0.0000025 + output * 0.000015
        )

    @property
    def name(self):
        return "gemini-2.5-pro"


class ClaudeSonnet4(LLMModel):
    def cost(self, input, output):
        return input * 0.000003 + output * 0.000015

    @property
    def name(self):
        return "claude-sonnet-4-20250514"


class ClaudeOpus4(LLMModel):
    def cost(self, input, output):
        return input * 0.000015 + output * 0.000075

    @property
    def name(self):
        return "claude-opus-4-20250514"


class Gemini25FlashLite(LLMModel):
    def cost(self, input, output):
        return input * 0.0000001 + output * 0.0000004

    @property
    def name(self):
        return "gemini-2.5-flash-lite"


class ClaudeSonnet45(LLMModel):
    def cost(self, input, output):
        return input * 0.000003 + output * 0.000015

    @property
    def name(self):
        return "claude-sonnet-4-5-20250929"


class GPT5(LLMModel):
    def cost(self, input, output):
        return input * 0.00000125 + output * 0.000010

    @property
    def name(self):
        return "gpt-5"


class GPT5Mini(LLMModel):
    def cost(self, input, output):
        return input * 0.00000025 + output * 0.000002

    @property
    def name(self):
        return "gpt-5-mini"


class GPT5Nano(LLMModel):
    def cost(self, input, output):
        return input * 0.00000005 + output * 0.0000004

    @property
    def name(self):
        return "gpt-5-nano"


class GPT41(LLMModel):
    def cost(self, input, output):
        return input * 0.000002 + output * 0.000008

    @property
    def name(self):
        return "gpt-4.1"


class O3(LLMModel):
    def cost(self, input, output):
        return input * 0.000002 + output * 0.000008

    @property
    def name(self):
        return "o3"


class GLM5(LLMModel):
    def cost(self, input, output):
        return input * 0.000001 + output * 0.0000032

    @property
    def name(self):
        return "zai-org/GLM-5"


def get_model(name: str) -> Optional[LLMModel]:
    models: dict[str, LLMModel] = {
        "gemini-2.5-pro": Gemini25Pro,
        "gemini-2.5-flash-lite": Gemini25FlashLite,
        "claude-sonnet-4-5-20250929": ClaudeSonnet45,
        "claude-sonnet-4-20250514": ClaudeSonnet4,
        "claude-opus-4-20250514": ClaudeOpus4,
        "gpt-5": GPT5,
        "gpt-5-mini": GPT5Mini,
        "gpt-5-nano": GPT5Nano,
        "gpt-4.1": GPT41,
        "grok-3": Grok3,
        "o3": O3,
        "glm5": GLM5,
    }

    if name in models:
        return models[name]
    return None
