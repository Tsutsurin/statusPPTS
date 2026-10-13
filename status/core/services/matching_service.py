"""Конвейер сопоставления: предобработка, индекс ППТС, анализ каждой уязвимости."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from status.core.constants import SOURCE_JOURNAL
from status.core.models import (
    AnalysisResult,
    JournalEntry,
    PipelineSettings,
    ScriptConfig,
    Software,
    Vulnerability,
)
from status.core.preprocessor import Preprocessor
from status.core.services.candidate_pool import CandidatePool
from status.core.services.exact_matcher import ExactMatcher
from status.core.services.scoring import Scorer
from status.core.services.status_assigner import StatusAssigner
from status.core.services.matching_worker import MatchingWorker

if TYPE_CHECKING:
    from status.ports.ml_port import VectorizerPort
    from status.ports.fuzzy_port import FuzzyMatcherPort
    from status.ports.db_port import RuleRepositoryPort

logger = logging.getLogger(__name__)


class ProgressCallback(Protocol):

    def __call__(self, stage: str, current: int, total: int) -> None: ...


def _noop_progress(stage: str, current: int, total: int) -> None:
    ...


class MatchingService:

    def __init__(
        self,
        settings: PipelineSettings,
        vectorizer: VectorizerPort,
        fuzzy_matcher: FuzzyMatcherPort,
        db_repo: RuleRepositoryPort | None = None,
    ) -> None:
        self._settings = settings
        self._vectorizer = vectorizer
        self._fuzzy_matcher = fuzzy_matcher
        self._db_repo = db_repo

        self._preprocessor = Preprocessor()
        self._exact_matcher = ExactMatcher()
        self._scorer = Scorer(
            weight_vector=settings.weight_vector,
            weight_fuzzy=settings.weight_fuzzy,
            weight_exact=settings.weight_exact,
        )
        self._status_assigner = StatusAssigner(
            auto_match_threshold=settings.auto_match_threshold,
            auto_match_margin=getattr(settings, "auto_match_margin", 0.0),
        )
        self._pool: CandidatePool | None = None
        self._progress: ProgressCallback = _noop_progress

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        self._progress = callback

    def run(
        self,
        vulnerabilities: list[Vulnerability],
        software_list: list[Software],
        journal_entries: list[JournalEntry] | None = None,
    ) -> list[AnalysisResult]:
        total = len(vulnerabilities)
        logger.info(
            "Pipeline started: %d vulnerabilities, %d software entries, %d journal entries",
            total,
            len(software_list),
            len(journal_entries) if journal_entries else 0,
        )

        journal_index: dict[str, list[JournalEntry]] = {}
        if journal_entries:
            self._progress("Загрузка журналов", 0, 1)
            for entry in journal_entries:
                if self._is_valid_cve(entry.cve_id):
                    cve = entry.cve_id.strip().upper()
                    journal_index.setdefault(cve, []).append(entry)
            self._progress("Загрузка журналов", 1, 1)
            logger.info("Journal index: %d unique CVEs", len(journal_index))

        self._progress("Препроцессинг", 0, total)
        vulns = self._run_preprocessing(vulnerabilities)

        kb_rules = []
        if self._settings.use_knowledge_base and self._db_repo:
            self._progress("Проверка по базе знаний", 0, total)
            try:
                kb_rules = self._db_repo.get_active_rules()
                logger.info("Loaded %d knowledge base rules", len(kb_rules))
            except Exception:
                logger.exception("Failed to load knowledge base rules")

        self._progress("Построение векторного индекса", 0, 1)
        self._vectorizer.build_index(software_list)
        self._pool = CandidatePool(software_list, channels=self._settings.candidate_channels)
        self._progress("Построение векторного индекса", 1, 1)

        worker = MatchingWorker(self)
        results: list[AnalysisResult] = []
        for i, vuln in enumerate(vulns):
            self._progress("Анализ уязвимостей", i, total)
            if (i + 1) % 100 == 0:
                logger.info("Processed %d / %d vulnerabilities", i + 1, total)
            result = worker.process_vulnerability(vuln, software_list, kb_rules, journal_index)
            results.append(result)

        self._progress("Анализ уязвимостей", total, total)

        if len(vulnerabilities) != len(results):
            logger.warning(
                "ВНИМАНИЕ: Количество входящих уязвимостей (%d) не совпадает с количеством результатов (%d)!",
                len(vulnerabilities),
                len(results),
            )

        n_journal = sum(1 for r in results if r.status_source == SOURCE_JOURNAL)
        logger.info(
            "Pipeline complete: %d results (%d from journal, %d НЕТ, %d manual review)",
            len(results),
            n_journal,
            sum(1 for r in results if r.status == "НЕТ"),
            sum(1 for r in results if r.status == ""),
        )
        return results

    def _run_preprocessing(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[Vulnerability]:
        if not self._settings.use_preprocessing:
            return vulnerabilities

        import re
        noise_pats = []
        if getattr(self._settings, "clean_noise_enabled", True) and getattr(self._settings, "clean_noise_patterns", ""):
            for line in self._settings.clean_noise_patterns.splitlines():
                line = line.strip()
                if line:
                    try:
                        noise_pats.append(re.compile(line, re.IGNORECASE))
                    except re.error:
                        logger.warning("Invalid clean_noise pattern skipped: %r", line)

        ver_pats = []
        if getattr(self._settings, "clean_versions_enabled", True) and getattr(self._settings, "clean_versions_patterns", ""):
            for line in self._settings.clean_versions_patterns.splitlines():
                line = line.strip()
                if line:
                    try:
                        ver_pats.append(re.compile(line, re.IGNORECASE))
                    except re.error:
                        logger.warning("Invalid clean_versions pattern skipped: %r", line)

        processed_vulns = []
        for v in vulnerabilities:
            prod = v.product
            if prod:
                for pat in noise_pats:
                    prod = pat.sub(" ", prod)
                for pat in ver_pats:
                    prod = pat.sub(" ", prod)
                prod = " ".join(prod.split())

            raw = " ".join(s for s in (v.vendor, prod, v.version) if s)
            processed_vulns.append(
                Vulnerability(
                    cve_id=v.cve_id,
                    vendor=v.vendor,
                    product=prod or v.product,
                    version=v.version,
                    raw_text=raw,
                    cvss=v.cvss,
                    source_url=v.source_url,
                    original_product=v.original_product or v.product,
                    pairs=v.pairs,
                )
            )

        return processed_vulns

    @staticmethod
    def _is_valid_cve(value: str) -> bool:
        if not value:
            return False
        v = value.strip().upper()
        return v not in ("NAN", "N/A", "NA", "NONE", "-", "") and v.startswith("CVE-")
