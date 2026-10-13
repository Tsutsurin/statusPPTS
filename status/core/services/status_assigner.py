"""Присвоение статуса паре: правила базы знаний, авто-ДА, НЕТ, ЛИНУКС, ручной разбор."""

from __future__ import annotations

import logging
import re

from status.core.constants import (
    MATCH_CONTAINS,
    MATCH_EXACT,
    MATCH_REGEX,
    MATCH_VECTOR,
    SOURCE_AUTO_NO_MATCH,
    SOURCE_AUTO_SCORE,
    SOURCE_CONFIDENT_NO,
    SOURCE_KNOWLEDGE_BASE,
    SOURCE_MANUAL,
    STATUS_EMPTY,
    STATUS_LINUX,
    STATUS_NO,
)
from status.core.models import (
    AnalysisResult,
    KnowledgeBaseRule,
    MatchCandidate,
    Software,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class StatusAssigner:

    def __init__(self, auto_match_threshold: float = 0.8, auto_match_margin: float = 0.0) -> None:
        self._auto_match_threshold = auto_match_threshold
        self._auto_match_margin = auto_match_margin

    def check_knowledge_base(
        self,
        vuln: Vulnerability,
        rules: list[KnowledgeBaseRule],
    ) -> tuple[KnowledgeBaseRule | None, bool]:
        for rule in rules:
            if self._rule_matches(vuln, rule):
                return rule, True
        return None, False

    def assign_status(
        self,
        vuln: Vulnerability,
        candidates: list[MatchCandidate],
        kb_rule: KnowledgeBaseRule | None = None,
    ) -> AnalysisResult:
        if kb_rule is not None:
            kb_candidate = MatchCandidate(
                software=Software(
                    id=kb_rule.ppts_id or "",
                    name=kb_rule.pattern,
                    vendor=kb_rule.vendor_pattern or "",
                    source="knowledge_base",
                ),
                vector_score=1.0,
                fuzzy_score=100.0,
                exact_score=100.0,
                combined_score=1.0,
                implied_status=kb_rule.status,
            )
            return AnalysisResult(
                vulnerability=vuln,
                status=kb_rule.status,
                status_source=SOURCE_KNOWLEDGE_BASE,
                candidates=[kb_candidate],
                ppts_id=kb_rule.ppts_id,
                match_type=kb_rule.match_type,
            )

        is_linux = (
            "linux" in (vuln.product or "").lower()
            or "linux" in (vuln.vendor or "").lower()
            or "linux" in (vuln.raw_text or "").lower()
        )

        if not candidates:
            return AnalysisResult(
                vulnerability=vuln,
                status=STATUS_LINUX if is_linux else STATUS_NO,
                status_source=SOURCE_AUTO_NO_MATCH,
                candidates=[],
                ppts_id=None,
                match_type=None,
            )

        best_candidate = candidates[0]
        runner_up = candidates[1].combined_score if len(candidates) > 1 else float("-inf")
        auto = (best_candidate.combined_score >= self._auto_match_threshold
                and best_candidate.combined_score - runner_up >= self._auto_match_margin)
        assigned_ppts_id = None
        if auto or (len(candidates) == 1 and not best_candidate.channel_only):
            assigned_ppts_id = best_candidate.software.id

        if is_linux:
            return AnalysisResult(
                vulnerability=vuln,
                status=STATUS_LINUX,
                status_source=SOURCE_AUTO_SCORE if auto else SOURCE_MANUAL,
                candidates=candidates,
                ppts_id=assigned_ppts_id,
                match_type="vector_fuzzy",
            )

        if auto:
            return AnalysisResult(
                vulnerability=vuln,
                status="ДА",
                status_source=SOURCE_AUTO_SCORE,
                candidates=candidates,
                ppts_id=best_candidate.software.id,
                match_type="vector_fuzzy",
            )

        return AnalysisResult(
            vulnerability=vuln,
            status=STATUS_EMPTY,
            status_source=SOURCE_MANUAL,
            candidates=candidates,
            ppts_id=assigned_ppts_id,
            match_type="vector_fuzzy",
        )

    def assign_confident_no(
        self, vuln: Vulnerability, candidates: list[MatchCandidate],
        min_score: float | None = None,
    ) -> AnalysisResult:
        if min_score is not None:
            candidates = [c for c in candidates
                          if c.channel_only or c.combined_score >= min_score]
        is_linux = any("linux" in (text or "").lower()
                       for text in (vuln.product, vuln.vendor, vuln.raw_text))
        return AnalysisResult(
            vulnerability=vuln,
            status=STATUS_LINUX if is_linux else STATUS_NO,
            status_source=SOURCE_CONFIDENT_NO,
            candidates=candidates,
            ppts_id=None,
            match_type="vector_fuzzy",
        )

    def _rule_matches(self, vuln: Vulnerability, rule: KnowledgeBaseRule) -> bool:
        if rule.vendor_pattern:
            if not self._pattern_matches(
                vuln.vendor, rule.vendor_pattern, rule.vendor_match_type, rule.id
            ):
                return False

        if rule.pattern:
            if not self._pattern_matches(
                vuln.product, rule.pattern, rule.match_type, rule.id
            ):
                if not self._pattern_matches(
                    vuln.raw_text, rule.pattern, rule.match_type, rule.id
                ):
                    return False

        if not rule.vendor_pattern and not rule.pattern:
            return False

        return True

    def _pattern_matches(
        self, text: str, pattern: str, match_type: str, rule_id: int | None
    ) -> bool:
        text_lower = text.lower()
        pattern_lower = pattern.lower()

        if match_type == MATCH_EXACT:
            return text_lower == pattern_lower

        if match_type == MATCH_CONTAINS:
            return pattern_lower in text_lower

        if match_type == MATCH_REGEX:
            try:
                return bool(re.search(pattern, text, re.IGNORECASE))
            except re.error:
                logger.warning("Invalid regex in rule %s: %r", rule_id, pattern)
                return False

        if match_type == MATCH_VECTOR:
            return False

        return False
