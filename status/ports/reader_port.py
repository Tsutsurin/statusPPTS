"""Интерфейс чтения ТСУ, ППТС и журнала публикаций."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from status.core.models import JournalEntry, PptsColumnMapping, Software, Vulnerability


class DataReaderPort(ABC):

    @abstractmethod
    def read_tsu(self, file_path: str | Path) -> list[Vulnerability]:
        ...

    @abstractmethod
    def read_ppts(
        self,
        file_path: str | Path,
        source: str,
        mapping: PptsColumnMapping | None = None,
    ) -> list[Software]:
        ...

    @abstractmethod
    def read_journal(
        self,
        file_path: str | Path,
        source_file: str = "",
    ) -> list[JournalEntry]:
        ...
