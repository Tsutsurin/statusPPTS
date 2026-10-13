"""Анализ одной уязвимости: разбор на пары, поиск кандидатов, статусы, объединение результатов."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from status.core.constants import PPTS_EMPTY_ID, STATUS_REPEAT
from status.core.models import (
    AnalysisResult,
    JournalEntry,
    MatchCandidate,
    PairAnalysisResult,
    Software,
    Vulnerability,
    VulnerabilityPair,
)
from status.core.services.candidate_pool import (
    block_auto_yes_with_os,
    confident_no,
    cut_for_duty,
)
from status.core.services.candidate_text import scoring_texts
from status.core.services.journal_apply import (
    STATUS_PRIORITY,
    apply_journal_to_pairs,
    get_overall_status,
    join_ppts_ids,
    overall_source,
    split_ppts_ids,
)

if TYPE_CHECKING:
    from status.core.services.matching_service import MatchingService

logger = logging.getLogger(__name__)


class MatchingWorker:

    def __init__(self, service: MatchingService) -> None:
        self._service = service
        self._settings = service._settings
        self._vectorizer = service._vectorizer
        self._fuzzy_matcher = service._fuzzy_matcher
        self._exact_matcher = service._exact_matcher
        self._scorer = service._scorer
        self._status_assigner = service._status_assigner
        self._db_repo = service._db_repo
        self._pool = getattr(service, "_pool", None)
        self._kb_hits: set[tuple[str, int]] = set()

    def process_vulnerability(
        self,
        vuln: Vulnerability,
        software_list: list[Software],
        kb_rules: list,
        journal_index: dict[str, list[JournalEntry]],
    ) -> AnalysisResult:
        _ensure_vuln_pairs(vuln)
        pair_results: list[PairAnalysisResult] = []
        for pair in vuln.pairs:
            sub_vuln = Vulnerability(
                cve_id=vuln.cve_id,
                vendor=pair.vendor,
                product=pair.product,
                version=" / ".join(pair.versions),
                raw_text=pair.raw_text,
                cvss=vuln.cvss,
                source_url=vuln.source_url,
                original_product=vuln.original_product,
                pairs=[pair],
            )
            sub_res = self._process_single(sub_vuln, software_list, kb_rules)
            pair_results.append(_pair_from_result(pair, sub_res))

        if not pair_results:
            sub_res = self._process_single(vuln, software_list, kb_rules)
            pair_results.append(
                PairAnalysisResult(
                    vendor=vuln.vendor,
                    product=vuln.product,
                    versions=[],
                    status=sub_res.status,
                    status_source=sub_res.status_source,
                    candidates=sub_res.candidates,
                    ppts_id=sub_res.ppts_id,
                    match_type=sub_res.match_type or "",
                )
            )

        block_auto_yes_with_os(pair_results, self._settings)
        cve_key = vuln.cve_id.strip().upper() if self._service._is_valid_cve(vuln.cve_id) else ""
        journal_hits = journal_index.get(cve_key, []) if journal_index and cve_key else []
        journal_no_candidates = apply_journal_to_pairs(pair_results, journal_hits)
        for pair_res in pair_results:
            pair_res.original_status = pair_res.status
            pair_res.original_ppts_id = pair_res.ppts_id
            pair_res.original_status_source = pair_res.status_source

        overall_ids: list[str] = []
        for pair_res in pair_results:
            if pair_res.exclude_from_report:
                continue
            overall_ids.extend(split_ppts_ids(pair_res.ppts_id))
        overall_status = get_overall_status([pr.status for pr in pair_results])
        overall_ppts = join_ppts_ids(overall_ids)
        if overall_ppts is None and overall_status == STATUS_REPEAT:
            overall_ppts = PPTS_EMPTY_ID

        return AnalysisResult(
            vulnerability=vuln,
            status=overall_status,
            status_source=overall_source({pr.status_source for pr in pair_results}),
            candidates=_merge_candidates(pair_results),
            ppts_id=overall_ppts,
            match_type=_overall_match_type(pair_results, bool(journal_hits)),
            responsible=None,
            journal_matches=journal_hits,
            pair_results=pair_results,
            journal_no_candidates=journal_no_candidates,
        )

    def _process_single(
        self,
        vuln: Vulnerability,
        software_list: list[Software],
        kb_rules: list,
    ) -> AnalysisResult:
        del software_list
        if kb_rules:
            matched_rule, matched = self._status_assigner.check_knowledge_base(vuln, kb_rules)
            if matched and matched_rule is not None:
                self._count_kb_hit(vuln.cve_id, matched_rule.id)
                return self._status_assigner.assign_status(vuln, [], kb_rule=matched_rule)

        if self._pool is not None:
            found = self._pool.gather(vuln.raw_text, vuln.vendor or "", vuln.product or "",
                                      self._vectorizer, self._settings)
        else:
            vector = self._vectorizer.search(vuln.raw_text, top_n=self._settings.top_n)
            gate_ok = any(score >= self._settings.vector_threshold for _, score in vector)
            found = [(sw, score, "", False) for sw, score in vector] if gate_ok else []
        if not found:
            return self._status_assigner.assign_status(vuln, [])

        candidate_sw = [sw for sw, _, _, _ in found]
        vector_scores = [score for _, score, _, _ in found]
        direction = self._settings.transliteration_direction
        texts = [
            scoring_texts(vuln.product or vuln.raw_text, vuln.vendor, sw.name, sw.vendor, direction)
            for sw in candidate_sw
        ]
        fuzzy_scores = [self._fuzzy_matcher.compute_score(query, name) for query, name in texts]
        exact_scores = [self._exact_matcher.score(query, name) for query, name in texts]
        candidates = self._scorer.build_candidates(
            candidate_sw, vector_scores, fuzzy_scores, exact_scores
        )
        channels = {id(sw): (channel, only) for sw, _, channel, only in found}
        for candidate in candidates:
            candidate.channel, candidate.channel_only = channels.get(id(candidate.software),
                                                                     ("", False))
        candidates = cut_for_duty(_trim_candidates(candidates, self._settings), self._settings)
        if confident_no(vuln.vendor or "", candidates, self._settings, self._pool):
            floor = self._settings.vector_threshold if self._settings.hide_weak_in_auto_no else None
            return self._status_assigner.assign_confident_no(vuln, candidates, floor)
        return self._status_assigner.assign_status(vuln, candidates)

    def _count_kb_hit(self, cve_id: str, rule_id: int | None) -> None:
        if self._db_repo is None or rule_id is None:
            return
        key = (cve_id.strip().upper(), rule_id)
        if key in self._kb_hits:
            return
        try:
            self._db_repo.increment_match_count(rule_id)
            self._kb_hits.add(key)
        except Exception:
            logger.exception("Failed to increment match count")


def _trim_candidates(candidates: list[MatchCandidate], settings) -> list[MatchCandidate]:
    mode = getattr(settings, "candidate_mode", "all")
    if not candidates or mode == "all":
        return candidates

    if mode == "vector_threshold":
        kept = [c for c in candidates if c.vector_score >= settings.vector_threshold]
    elif mode == "relative":
        ratio = getattr(settings, "candidate_relative", 0.75)
        best = candidates[0].combined_score
        kept = [c for c in candidates if c.combined_score >= best * ratio]
    else:
        logger.warning("Unknown candidate_mode %r, keeping all candidates", mode)
        return candidates

    return kept or candidates[:1]


def _overall_match_type(pair_results: list[PairAnalysisResult], has_journal: bool) -> str:
    if has_journal:
        return "journal"
    if not pair_results:
        return "pair_matching"
    best = max(pair_results, key=lambda item: STATUS_PRIORITY.get(item.status, 0))
    return best.match_type or "pair_matching"


def _pair_from_result(pair: VulnerabilityPair, sub_res: AnalysisResult) -> PairAnalysisResult:
    return PairAnalysisResult(
        vendor=pair.vendor,
        product=pair.product,
        versions=pair.versions,
        status=sub_res.status,
        status_source=sub_res.status_source,
        candidates=sub_res.candidates,
        ppts_id=sub_res.ppts_id,
        match_type=sub_res.match_type or "",
    )


def _ensure_vuln_pairs(vuln: Vulnerability) -> None:
    if vuln.pairs:
        return
    product = vuln.product or ""
    from status.core.services.normalizer import parse_fstek_pairs

    parsed_groups = parse_fstek_pairs(product)
    if " - " in product and parsed_groups:
        for vendor, prod, versions in parsed_groups:
            raw = " ".join(part for part in (vendor, prod) if part)
            vuln.pairs.append(
                VulnerabilityPair(vendor=vendor, product=prod, versions=versions, raw_text=raw)
            )
        return
    parts: list[str] = []
    if product:
        raw_parts = re.split(
            r"\s*(?:;|,|\s+и\s+(?!(?:ниже|выше|ранее|позднее|более)\b)|\s*/\s*)\s*",
            product,
            flags=re.IGNORECASE,
        )
        for part in raw_parts:
            cleaned = part.strip()
            if cleaned and len(cleaned) >= 2 and cleaned.lower() not in ("и", "or", "and"):
                parts.append(cleaned)
    for part in parts:
        raw = " ".join(item for item in (vuln.vendor, part) if item)
        vuln.pairs.append(
            VulnerabilityPair(vendor=vuln.vendor, product=part, versions=[], raw_text=raw)
        )


def _merge_candidates(pair_results: list[PairAnalysisResult]) -> list[MatchCandidate]:
    best: dict[str, MatchCandidate] = {}
    for pair_res in pair_results:
        for candidate in pair_res.candidates:
            current = best.get(candidate.software.id)
            if current is None or candidate.combined_score > current.combined_score:
                best[candidate.software.id] = candidate
    merged = list(best.values())
    merged.sort(key=lambda item: item.combined_score, reverse=True)
    return merged
