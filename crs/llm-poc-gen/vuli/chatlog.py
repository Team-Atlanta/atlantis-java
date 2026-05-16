from pathlib import Path
from typing import Optional

from langchain_core.messages import BaseMessage

from vuli.common.singleton import Singleton


class ChatLog(metaclass=Singleton):
    def __init__(self):
        self._dir: Optional[Path] = None
        self._counters: dict[str, int] = {}

    def initialize(self, output_dir: Path) -> None:
        self._dir = output_dir / "llm-chats"
        self._dir.mkdir(exist_ok=True)

    def log(
        self, agent: str, model: str, messages: list[BaseMessage], response: BaseMessage
    ) -> None:
        if self._dir is None:
            return
        seq = self._counters.get(agent, 0) + 1
        self._counters[agent] = seq
        path = self._dir / f"{agent}-{seq:03d}.log"
        with open(path, "w") as f:
            f.write(f"Model: {model}\n\n")
            for msg in messages:
                f.write(f"{msg.pretty_repr()}\n\n")
            f.write("--- Response ---\n\n")
            f.write(f"{response.pretty_repr()}\n")
