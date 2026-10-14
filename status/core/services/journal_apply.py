"""Применение журнала публикаций: ПОВТОР, ID из журнала, общий статус строки."""

from __future__ import annotations

import re

from status.core.constants import (
    PPTS_EMPTY_ID,
    SOURCE_AUTO_NO_MATCH,
    SOURCE_AUTO_SCORE,
    SOURCE_CONFIDENT_NO,
    SOURCE_JOURNAL,
    SOURCE_KNOWLEDGE_BASE,
    SOURCE_MANUAL,
    STATUS_CONDITIONAL,
    STATUS_EMPTY,
    STATUS_LINUX,
    STATUS_NO,
    STATUS_REPEAT,
    STATUS_YES,
)
from status.core.models import JournalEntry, PairAnalysisResult

_DASH_IDS = frozenset(
    {"----------", "-----------", "—", "–", "N/A", "n/a", "-", "None"}
)

STATUS_PRIORITY: dict[str, int] = {
    STATUS_REPEAT: 5,
    STATUS_YES: 4,
    STATUS_CONDITIONAL: 3,
    STATUS_LINUX: 2,
    STATUS_EMPTY: 1,
    STATUS_NO: 0,
}

_STATUS_ALIASES = {
    "LINUX": STATUS_LINUX,
    "CONDITIONAL": STATUS_CONDITIONAL,
    "REPEAT": STATUS_REPEAT,
    "YES": STATUS_YES,
    "NO": STATUS_NO,
    "ПОВТОР": STATUS_REPEAT,
    "УСЛОВНО": STATUS_CONDITIONAL,
    "ЛИНУКС": STATUS_LINUX,
    "ДА": STATUS_YES,
    "НЕТ": STATUS_NO,
}


def normalize_status(value: str) -> str:
    raw = (value or "").strip().upper()
    if raw in _STATUS_ALIASES:
        return _STATUS_ALIASES[raw]
    return raw


def split_ppts_ids(raw: str | None) -> list[str]:
    if not raw:
        return []
    tokens: list[str] = []
    for part in re.split(r"[\n/]", raw):
        token = part.strip()
        if not token or token in _DASH_IDS or re.match(r"^-+$", token):
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens


def join_ppts_ids(ids: list[str]) -> str | None:
    unique: list[str] = []
    for item in ids:
        if item and item not in unique:
            unique.append(item)
    return "\n".join(unique) if unique else None


def pick_status(statuses: list[str]) -> str:
    if not statuses:
        return STATUS_EMPTY
    normalized = [normalize_status(item) for item in statuses]
    return max(normalized, key=lambda item: STATUS_PRIORITY.get(item, 0))


def get_overall_status(pair_statuses: list[str]) -> str:
    if not pair_statuses:
        return STATUS_EMPTY
    cleaned = [normalize_status(item) for item in pair_statuses if item]
    has_empty = len(cleaned) < len(pair_statuses)
    for status in (
        STATUS_REPEAT,
        STATUS_YES,
        STATUS_CONDITIONAL,
        STATUS_LINUX,
    ):
        if status in cleaned:
            return status
    if has_empty:
        return STATUS_EMPTY
    return STATUS_NO


def overall_source(sources: set[str]) -> str:
    order = (
        SOURCE_MANUAL,
        SOURCE_JOURNAL,
        SOURCE_KNOWLEDGE_BASE,
        SOURCE_AUTO_SCORE,
        SOURCE_CONFIDENT_NO,
        SOURCE_AUTO_NO_MATCH,
    )
    for item in order:
        if item in sources:
            return item
    return SOURCE_AUTO_NO_MATCH


def collect_journal_ids(hits: list[JournalEntry]) -> list[str]:
    ids: list[str] = []
    for hit in hits:
        for token in split_ppts_ids(hit.ppts_id):
            if token not in ids:
                ids.append(token)
    return ids


def _pair_candidate_ids(pair: PairAnalysisResult) -> list[str]:
    ids: list[str] = []
    for candidate in pair.candidates:
        token = (candidate.software.id or "").strip()
        if token and token not in ids and token not in _DASH_IDS:
            ids.append(token)
    for token in split_ppts_ids(pair.ppts_id):
        if token not in ids:
            ids.append(token)
    return ids


def apply_journal_to_pairs(
    pair_results: list[PairAnalysisResult],
    journal_hits: list[JournalEntry],
) -> bool:
    if not journal_hits or not pair_results:
        return False

    journal_ids = collect_journal_ids(journal_hits)
    journal_statuses = [
        normalize_status(hit.status) for hit in journal_hits if hit.status and hit.status.strip()
    ]
    has_candidates = any(pair.candidates for pair in pair_results)
    if not has_candidates:
        joined = join_ppts_ids(journal_ids) or PPTS_EMPTY_ID
        for pair in pair_results:
            pair.status = STATUS_REPEAT
            pair.ppts_id = joined
            pair.status_source = SOURCE_JOURNAL
        return True

    journal_id_set = set(journal_ids)
    matched_per_pair: list[list[str]] = []
    extras_per_pair: list[list[str]] = []
    covered: list[str] = []
    for pair in pair_results:
        coverage_ids = _pair_candidate_ids(pair)
        matched = [item for item in coverage_ids if item in journal_id_set]
        extras = [item for item in split_ppts_ids(
            pair.ppts_id) if item not in journal_id_set]
        matched_per_pair.append(matched)
        extras_per_pair.append(extras)
        covered.extend(matched)

    covered_set = set(covered)
    uncovered = [item for item in journal_ids if item not in covered_set]
    any_matched = bool(covered_set)

    for pair, matched, extras in zip(pair_results, matched_per_pair, extras_per_pair, strict=True):
        matching_status = pair.status
        ids: list[str] = []
        if any_matched:
            ids.extend(matched)
            ids.extend(uncovered)
        else:
            ids.extend(journal_ids)
        ids.extend(extras)
        pair.ppts_id = join_ppts_ids(ids)
        if pair.ppts_id is None and not journal_ids:
            pair.ppts_id = PPTS_EMPTY_ID
        if extras:
            pair.status = pick_status([*journal_statuses, matching_status])
        else:
            pair.status = STATUS_REPEAT
        pair.status_source = SOURCE_JOURNAL
    return False
