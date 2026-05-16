#!/usr/bin/env python3

import logging
import os
import shlex
import sys

logger = logging.getLogger(__name__)

SENSITIVE_ENV_VARS = [
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
    "LITELLM_KEY",
    "GITHUB_TOKEN",
    "GITHUB_USER",
]


def CRS_ERR_LOG(mod: str) -> str:
    return f"CRS-JAVA-ERR-sinkpicker-{mod}"


def CRS_WARN_LOG(mod: str) -> str:
    return f"CRS-JAVA-WARN-sinkpicker-{mod}"


def get_env_or_abort(env_name: str) -> str:
    env_value = os.getenv(env_name)
    if env_value is None:
        print(f"Environment variable {env_name} is not set.", file=sys.stderr)
        sys.exit(1)
    return env_value


def sanitize_env(env: dict) -> dict:
    """Remove sensitive environment variables from the environment."""
    global SENSITIVE_ENV_VARS

    new_env = env.copy()
    for var in SENSITIVE_ENV_VARS:
        new_env.pop(var, None)

    return new_env


def get_env_exports(env: dict) -> str:
    """Return a string that can be used to export the environment variables."""
    return "\n".join(
        f"export {k}={shlex.quote(v)}" for k, v in sanitize_env(env).items()
    )


def get_usable_cpu_id():
    """
    Get a usable CPU ID for binding tasks.

    Returns:
        int: A CPU ID that can be used for binding tasks (0 if none found)
    """
    try:
        cpu_affinity = os.sched_getaffinity(0)
        if cpu_affinity:
            # If bound to any cores, return the first one
            cpu_id = list(cpu_affinity)[0]
            logger.info(
                f"Using CPU ID {cpu_id} (bound to cores {sorted(list(cpu_affinity))})"
            )
            return cpu_id
    except Exception as e:
        logger.warning(f"{CRS_ERR_LOG("cpu")} Could not determine CPU affinity: {e}")

    logger.info("Defaulting to CPU 0")
    return 0


def get_with_model_provider(model_name: str) -> str:
    """Infer the model provider from the model name."""
    model_name = model_name.lower()
    if model_name.startswith("vertex"):
        return "vertex_ai/openai/" + model_name.split("/")[-1] + "-maas"
    elif model_name.startswith("gpt") or model_name.startswith("o1") or model_name.startswith("o3-"):
        return "openai/" + model_name
    elif model_name.startswith("claude-"):
        return "anthropic/" + model_name
    elif model_name.startswith("gemini-"):
        return "gemini/" + model_name
    elif model_name.startswith("grok-"):
        return "xai/" + model_name
    elif model_name.startswith("zai-"):
        return "vertex_ai/" + model_name + "-maas"
    else:
        return "unknown"
