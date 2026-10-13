"""Интерфейс записи отчёта."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from status.core.models import AnalysisResult, PipelineSettings


class ReportWriterPort(ABC):

    @abstractmethod
    def write_report(
        self,
        path: Path,
        results: list[AnalysisResult],
        settings: PipelineSettings,
        responsible: str = "",
        publication: str = "БДУ ФСТЕК",
        journal_source_urls: set[str] | None = None,
    ) -> None:
        ...
