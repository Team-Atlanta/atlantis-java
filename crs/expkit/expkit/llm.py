#!/usr/bin/env python3

import logging
import os
import time

import litellm
import openai
from litellm import completion, completion_cost

from .utils import CRS_ERR_LOG, CRS_WARN_LOG

CRS_ERR = CRS_ERR_LOG("llm")
CRS_WARN = CRS_WARN_LOG("llm")


logger = logging.getLogger(__name__)


class LLMClient:
    """
    A client for multi-provider LLM API calls using litellm with unified interface,
    error handling, and usage tracking.
    """

    def __init__(
        self, timeout: int = 240, max_retries: int = 10, verbose: bool = False
    ):
        self.api_key = os.environ.get("LITELLM_KEY") or (open(os.environ["OSS_CRS_LLM_API_KEY_FILE"]).read().strip() if os.environ.get("OSS_CRS_LLM_API_KEY_FILE") else os.environ.get("OSS_CRS_LLM_API_KEY"))
        self.base_url = os.environ.get("AIXCC_LITELLM_HOSTNAME") or os.environ.get("OSS_CRS_LLM_API_URL")

        if not self.api_key:
            logger.error(f"{CRS_WARN} LITELLM_KEY environment variable not set")
            raise ValueError("LITELLM_KEY environment variable must be set")

        if not self.base_url:
            logger.error(
                f"{CRS_ERR} AIXCC_LITELLM_HOSTNAME environment variable not set"
            )
            raise ValueError("AIXCC_LITELLM_HOSTNAME environment variable must be set")

        # Configure litellm defaults
        litellm.drop_params = True
        litellm.request_timeout = timeout
        litellm.num_retries = max_retries
        litellm.set_verbose = verbose

        # Usage tracking
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.request_count = 0

    def completion(
        self,
        prompt: str,
        model: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        tools: list[dict] | None = None,
        tool_choice: str | dict | None = None,
    ) -> dict:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        params = {
            "model": model,
            "messages": messages,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "request_timeout": litellm.request_timeout,
        }

        params["temperature"] = temperature if temperature is not None else 1.0
        if tools:
            params["tools"] = tools
        if tool_choice:
            params["tool_choice"] = tool_choice

        if "claude" in model:
            params["max_tokens"] = 32000
            params["thinking"] = {"type": "enabled", "budget_tokens": 20000}
            params["temperature"] = 1

        try:
            start_time = time.time()

            if "claude" in model:
                response = completion(**params)
            else:
                cli = openai.OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                )
                response = cli.chat.completions.create(model=model, messages=messages)

            return self._process_response(response, params["model"], start_time)

        except Exception as e:
            logger.error(
                f"{CRS_WARN} Error in completion request: {str(e)}", exc_info=True
            )
            raise

    def _process_response(self, response, model, start_time):
        first_choice = response.choices[0]
        if hasattr(first_choice, "message") and hasattr(
            first_choice.message, "content"
        ):
            content = first_choice.message.content
        else:
            content = str(first_choice)

        cost = completion_cost(completion_response=response)
        self._update_metrics(response, cost)

        elapsed = time.time() - start_time
        logger.info(f"Request completed in {elapsed:.2f}s, cost: ${cost:.6f}")

        return {
            "content": content,
            "cost": cost,
            "elapsed_time": elapsed,
            "model": model,
            "usage": (
                response.usage.model_dump() if hasattr(response, "usage") else None
            ),
            "tool_calls": (
                first_choice.message.tool_calls
                if hasattr(first_choice.message, "tool_calls")
                else None
            ),
            "raw_response": response,
        }

    def _update_metrics(self, response, cost):
        """Update internal tracking metrics"""
        self.total_cost += cost
        self.request_count += 1

        if hasattr(response, "usage"):
            self.total_tokens += response.usage.total_tokens
            self.total_prompt_tokens += response.usage.prompt_tokens
            self.total_completion_tokens += response.usage.completion_tokens

    def get_usage_stats(self) -> dict:
        """Get detailed usage statistics for all requests made through this client"""
        return {
            "total_cost": self.total_cost,
            "total_tokens": self.total_tokens,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "request_count": self.request_count,
            "average_cost_per_request": (
                self.total_cost / self.request_count if self.request_count else 0
            ),
            "average_tokens_per_request": (
                self.total_tokens / self.request_count if self.request_count else 0
            ),
        }

    def print_usage_stats(self) -> str:
        """Format usage statistics as a human-readable string"""
        stats = self.get_usage_stats()

        return (
            f"LLM Usage Statistics:\n"
            f"  Total Requests: {stats['request_count']}\n"
            f"  Total Cost: ${stats['total_cost']:.6f}\n"
            f"  Total Tokens: {stats['total_tokens']}\n"
            f"    - Prompt Tokens: {stats['total_prompt_tokens']}\n"
            f"    - Completion Tokens: {stats['total_completion_tokens']}\n"
            f"  Average Cost per Request: ${stats['average_cost_per_request']:.6f}\n"
            f"  Average Tokens per Request: {int(stats['average_tokens_per_request'])}\n"
        )
