from __future__ import annotations

from pufcli.models.session import ScanSession


class SessionStore:
    def __init__(self) -> None:
        self._sessions: list[ScanSession] = []
        self._counter = 0

    def add(self, kind: str, target: str, command: str, results: list[dict]) -> ScanSession:
        self._counter += 1
        session = ScanSession(
            id=self._counter,
            kind=kind,
            target=target,
            command=command,
            results=results,
        )
        self._sessions.append(session)
        return session

    def list(self) -> list[ScanSession]:
        return list(self._sessions)

    def get(self, session_id: int) -> ScanSession | None:
        for session in self._sessions:
            if session.id == session_id:
                return session
        return None
