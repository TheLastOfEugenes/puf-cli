from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

@dataclass
class ScanSession:
    id: int
    kind: str
    target: str
    status: str = "done"
    progress: int = 100
    created_at: datetime = field(default_factory=datetime.now)
    command: str = ""
    results: list[dict[str, Any]] = field(default_factory=list)