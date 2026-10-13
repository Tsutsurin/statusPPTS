"""Нечёткое сравнение названий (RapidFuzz)."""

from __future__ import annotations

import logging

from rapidfuzz import fuzz

from status.core.constants import DEFAULT_FUZZY_THRESHOLD, DEFAULT_MIN_WORD_LENGTH
from status.ports.fuzzy_port import FuzzyMatcherPort

logger = logging.getLogger(__name__)

_STOPWORDS = frozenset(
    {"a", "an", "the", "of", "for", "and", "or", "to", "in", "on", "by", "with",
     "и", "в", "на", "для", "по", "с", "или", "i", "v", "na", "dlja", "po", "s", "ili"}
)


class RapidFuzzAdapter(FuzzyMatcherPort):

    def __init__(
        self,
        threshold: int = DEFAULT_FUZZY_THRESHOLD,
        min_word_length: int = DEFAULT_MIN_WORD_LENGTH,
    ) -> None:
        self._threshold = threshold
        self._min_word_length = min_word_length

    def compute_score(self, text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 0.0

        a = self._prepare(text1)
        b = self._prepare(text2)

        if not a or not b:
            return 0.0

        token_sort = fuzz.token_sort_ratio(a, b)
        token_set = fuzz.token_set_ratio(a, b)
        partial = fuzz.partial_ratio(a, b)

        return max(token_sort, token_set, partial)

    def compute_scores_batch(self, query: str, choices: list[str]) -> list[float]:
        return [self.compute_score(query, choice) for choice in choices]

    def is_match(self, text1: str, text2: str) -> bool:
        return self.compute_score(text1, text2) >= self._threshold

    def _prepare(self, text: str) -> str:
        words = text.lower().split()
        filtered = [
            w
            for w in words
            if w not in _STOPWORDS
            and (len(w) >= self._min_word_length or any(ch.isdigit() for ch in w))
        ]
        return " ".join(filtered) if filtered else text.lower()
