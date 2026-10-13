"""Интерфейс внешнего парсера уязвимостей."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt
    from pathlib import Path


class ParserError(RuntimeError):
    ...


class VulnerabilityParserPort(ABC):

    @abstractmethod
    def latest_bdu_id(self) -> str:
        ...

    @abstractmethod
    def parse_fstek(self, start: str, end: str, workers: int, output: Path) -> Path:
        ...

    @abstractmethod
    def parse_news(self, date: dt.date, output: Path) -> Path:
        ...

    def progress(self) -> tuple[int, int] | None:
        return None

    @abstractmethod
    def cancel(self) -> None:
        ...
