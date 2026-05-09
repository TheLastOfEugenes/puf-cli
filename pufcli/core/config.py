from __future__ import annotations

import configparser
from pathlib import Path


class PufConfig:
    def __init__(self, path: str | Path = "puf.conf") -> None:
        self.path = Path(path)
        self.parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
        self.reload()

    def reload(self) -> None:
        self.parser.read(self.path)

    def get_wordlist(self, kind: str) -> str:
        return self.parser.get("wordlists", kind, fallback="").strip()

    def get_command(self, kind: str) -> str:
        return self.parser.get("commands", kind, fallback="").strip()