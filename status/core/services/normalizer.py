"""Нормализация текста: транслитерация, разбор строк ФСТЭК и RSS на пары «вендор — продукт»."""

from __future__ import annotations

import logging
import re

from transliterate import translit

logger = logging.getLogger(__name__)

_SKIP_PATTERNS = re.compile(
    r"\b(?:CVE-\d{4}-\d+|http[s]?://\S+|[A-Z]{2,}-\d+)\b",
    re.IGNORECASE,
)


def normalize_text(text: str, direction: str = "to_en") -> str:
    if not text or not text.strip():
        return text

    text = text.strip().lower()

    if direction == "to_en":
        return _to_latin(text)
    if direction == "to_ru":
        return _to_cyrillic(text)

    logger.warning(
        "Unknown transliteration direction: %r, defaulting to 'to_en'", direction)
    return _to_latin(text)


def _to_latin(text: str) -> str:
    if not _has_cyrillic(text):
        return text
    try:
        return translit(text, "ru", reversed=True)
    except Exception:
        logger.debug("Transliteration to Latin failed for: %r", text)
        return text


def _to_cyrillic(text: str) -> str:
    if not _has_latin(text):
        return text
    try:
        return translit(text, "ru")
    except Exception:
        logger.debug("Transliteration to Cyrillic failed for: %r", text)
        return text


def _has_cyrillic(text: str) -> bool:
    return bool(re.search(r"[а-яёА-ЯЁ]", text))


def _has_latin(text: str) -> bool:
    return bool(re.search(r"[a-zA-Z]", text))


def parse_fstek_pairs(combined_product: str) -> list[tuple[str, str, list[str]]]:
    if not combined_product:
        return []

    if " - " in combined_product:
        raw_parts = [p.strip()
                     for p in combined_product.split(",") if p.strip()]

        merged_parts = []
        temp = []
        for part in raw_parts:
            temp.append(part)
            if " - " in part:
                merged_parts.append(", ".join(temp))
                temp = []
        if temp:
            if merged_parts:
                merged_parts[-1] = merged_parts[-1] + ", " + ", ".join(temp)
            else:
                merged_parts.append(", ".join(temp))

        groups: list[tuple[str, str, list[str]]] = []
        for item in merged_parts:
            parts = [p.strip() for p in item.split(" - ")]
            if len(parts) >= 3:
                vendor = parts[0]
                products_raw = parts[1]
                version = " - ".join(parts[2:])
                prods = [pr.strip()
                         for pr in products_raw.split(",") if pr.strip()]
                for prod in prods:
                    _append_to_groups(groups, vendor, prod, version)
            elif len(parts) == 2:
                vendor = parts[0]
                products_raw = parts[1]
                prods = [pr.strip()
                         for pr in products_raw.split(",") if pr.strip()]
                for prod in prods:
                    _append_to_groups(groups, vendor, prod, "")
            else:
                _append_to_groups(groups, "", parts[0], "")

        return groups
    else:
        vendor, product = _split_vendor_product(combined_product)
        return [(vendor, product, [])]


def _append_to_groups(
    groups: list[tuple[str, str, list[str]]],
    vendor: str,
    product: str,
    version: str,
) -> None:
    found = False
    for g in groups:
        if g[0].lower() == vendor.lower() and g[1].lower() == product.lower():
            if version and version not in g[2]:
                g[2].append(version)
            found = True
            break
    if not found:
        versions_list = [version] if version else []
        groups.append((vendor, product, versions_list))


def _split_vendor_product(text: str) -> tuple[str, str]:
    if not text:
        return "", ""
    seps = re.compile(r"\s*(?:,\s+|\s+-\s+)\s*")
    parts = seps.split(text, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return "", text.strip()
