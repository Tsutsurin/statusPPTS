"""Идентификаторы БДУ ФСТЭК: максимум по журналу и диапазон для парсера."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

BduId = tuple[int, int]

_ID_IN_TEXT_RE = re.compile(r"(?:vul/|BDU:\s*)(\d{4})-(\d{1,6})\b", re.IGNORECASE)
_BARE_ID_RE = re.compile(r"^(?:BDU:\s*)?(\d{4})-(\d{1,6})$", re.IGNORECASE)


@dataclass(frozen=True)
class BduRange:

    start: str
    end: str
    journal_max: str
    up_to_date: bool


def format_bdu_id(bdu_id: BduId) -> str:
    return f"{bdu_id[0]}-{bdu_id[1]:05d}"


def parse_bdu_id(text: str) -> BduId | None:
    value = (text or "").strip()
    match = _BARE_ID_RE.match(value) or _ID_IN_TEXT_RE.search(value)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def max_bdu_id(urls: Iterable[str]) -> BduId | None:
    best: BduId | None = None
    for url in urls:
        if "bdu.fstec.ru" not in (url or "").lower():
            continue
        for match in _ID_IN_TEXT_RE.finditer(url):
            found = (int(match.group(1)), int(match.group(2)))
            if best is None or found > best:
                best = found
    return best


def suggest_range(journal_max: BduId | None, latest: BduId) -> BduRange:
    end = format_bdu_id(latest)
    max_text = format_bdu_id(journal_max) if journal_max else ""
    if journal_max is None:
        return BduRange(start=end, end=end, journal_max="", up_to_date=False)
    if journal_max >= latest:
        return BduRange(start="", end=end, journal_max=max_text, up_to_date=True)
    if latest[0] > journal_max[0]:
        start: BduId = (latest[0], 1)
    else:
        start = (journal_max[0], journal_max[1] + 1)
    return BduRange(start=format_bdu_id(start), end=end, journal_max=max_text, up_to_date=False)


def validate_range(start: str, end: str) -> tuple[BduId, BduId]:
    first, last = parse_bdu_id(start), parse_bdu_id(end)
    if first is None or last is None:
        raise ValueError("Укажите ID в формате 2026-00001")
    if first[0] != last[0]:
        raise ValueError(
            "Парсер берёт диапазон в пределах одного года: разбейте его на два запуска"
        )
    if last[1] < first[1]:
        raise ValueError("Конец диапазона меньше начала")
    return first, last
