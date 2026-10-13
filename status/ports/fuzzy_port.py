"""Интерфейс нечёткого сравнения."""

from __future__ import annotations

from abc import ABC, abstractmethod


class FuzzyMatcherPort(ABC):

    @abstractmethod
    def compute_score(self, text1: str, text2: str) -> float:
        ...

    @abstractmethod
    def compute_scores_batch(self, query: str, choices: list[str]) -> list[float]:
        ...
