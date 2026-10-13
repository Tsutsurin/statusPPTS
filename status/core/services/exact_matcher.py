"""Точное совпадение названий (балл exact)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ExactMatcher:

    def score(self, query: str, candidate: str) -> float:
        if not query or not candidate:
            return 0.0

        q = query.strip().lower()
        c = candidate.strip().lower()

        legacy_score = 0.0
        if q == c:
            legacy_score = 100.0
        elif q in c or c in q:
            legacy_score = 75.0
        else:
            q_words = set(q.split())
            c_words = set(c.split())
            if q_words and q_words.issubset(c_words):
                legacy_score = 50.0

        if legacy_score > 0.0:
            return legacy_score

        q_words = [w for w in q.split() if w]
        c_words_set = set(c.split())
        if not q_words:
            return 0.0

        matched = sum(1 for w in q_words if w in c_words_set)
        return round((matched / len(q_words)) * 100.0, 2)

    def score_candidates(
        self,
        query: str,
        candidate_names: list[str],
    ) -> list[float]:
        return [self.score(query, name) for name in candidate_names]
