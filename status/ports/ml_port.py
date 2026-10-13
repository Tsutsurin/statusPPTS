"""Интерфейс векторного поиска."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from status.core.models import Software


class VectorizerPort(ABC):

    @abstractmethod
    def build_index(self, software_list: list[Software]) -> None:
        ...

    @abstractmethod
    def search(self, query: str, top_n: int = 10) -> list[tuple[Software, float]]:
        ...

    @abstractmethod
    def batch_search(
        self,
        queries: list[str],
        top_n: int = 10,
    ) -> list[list[tuple[Software, float]]]:
        ...
