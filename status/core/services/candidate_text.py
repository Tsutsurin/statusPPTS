"""Тексты для сравнения: продукт и название позиции ППТС без слов вендора."""

from __future__ import annotations

import re

from status.core.services.normalizer import normalize_text

_EDGE_CHARS = ".,;:()[]\"'«»-–—"
_VENDOR_SPLIT = re.compile(r"[\s,;/]+")


def _clean(token: str) -> str:
    return token.strip(_EDGE_CHARS)


def vendor_tokens(vendors: list[str], direction: str = "to_en") -> set[str]:
    tokens: set[str] = set()
    for vendor in vendors:
        normalized = normalize_text(vendor or "", direction=direction) or ""
        for raw in _VENDOR_SPLIT.split(normalized):
            token = _clean(raw)
            if token:
                tokens.add(token)
    return tokens


def strip_vendor(text: str, tokens: set[str], direction: str = "to_en") -> str:
    normalized = normalize_text(text or "", direction=direction) or ""
    kept = [raw for raw in normalized.split() if _clean(
        raw) and _clean(raw) not in tokens]
    return " ".join(kept)


def scoring_texts(
    product: str,
    vendor: str,
    candidate_name: str,
    candidate_vendor: str,
    direction: str = "to_en",
) -> tuple[str, str]:
    tokens = vendor_tokens([vendor, candidate_vendor], direction)
    query = strip_vendor(product, tokens, direction)
    candidate = strip_vendor(candidate_name, tokens, direction)
    if query and candidate:
        return query, candidate
    full_query = (normalize_text(
        product or "", direction=direction) or "").strip()
    full_candidate = (normalize_text(candidate_name or "",
                      direction=direction) or "").strip()
    return full_query, full_candidate
