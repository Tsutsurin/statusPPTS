"""Общий балл кандидата из векторного, нечёткого и точного сравнения."""

from __future__ import annotations

import logging

from status.core.models import MatchCandidate, Software

logger = logging.getLogger(__name__)

WEIGHT_VECTOR = 0.35
WEIGHT_FUZZY = 0.40
WEIGHT_EXACT = 0.25


class Scorer:

    def __init__(
        self,
        weight_vector: float = WEIGHT_VECTOR,
        weight_fuzzy: float = WEIGHT_FUZZY,
        weight_exact: float = WEIGHT_EXACT,
    ) -> None:
        self._wv = weight_vector
        self._wf = weight_fuzzy
        self._we = weight_exact

    def compute_combined(
        self,
        vector_score: float,
        fuzzy_score: float,
        exact_score: float,
    ) -> float:
        fuzzy_norm = fuzzy_score / 100.0
        exact_norm = exact_score / 100.0

        return (
            self._wv * vector_score
            + self._wf * fuzzy_norm
            + self._we * exact_norm
        )

    def build_candidates(
        self,
        software_list: list[Software],
        vector_scores: list[float],
        fuzzy_scores: list[float],
        exact_scores: list[float],
    ) -> list[MatchCandidate]:
        candidates: list[MatchCandidate] = []
        for sw, vs, fs, es in zip(
            software_list, vector_scores, fuzzy_scores, exact_scores, strict=True
        ):
            combined = self.compute_combined(vs, fs, es)
            candidates.append(
                MatchCandidate(
                    software=sw,
                    vector_score=vs,
                    fuzzy_score=fs,
                    exact_score=es,
                    combined_score=combined,
                )
            )

        candidates.sort(key=lambda c: c.combined_score, reverse=True)
        return candidates
