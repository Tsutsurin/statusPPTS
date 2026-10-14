"""Поиск кандидатов по редкому слову названия и по вендору — в дополнение к векторному поиску."""

from __future__ import annotations

import re
from collections.abc import Sequence

from status.core.models import Software

WORD_DF_MAX = 10
WORD_LIMIT = 5
VENDOR_MAX = 3
MIN_WORD = 3

_WORD_RE = re.compile(r"[^\W_]+")
_LEGAL = frozenset("""
inc incorporated corp corporation co company ltd limited llc gmbh ag sa srl bv plc the
ооо ао зао пао оао нпо фгуп ип
""".split())
_STOP = _LEGAL | frozenset("""
server client edition enterprise professional pro standard community express lite basic
premium ultimate home personal free open source for and with update service pack patch
plugin addon extension module library driver firmware sdk api web mobile desktop cloud
agent manager management console portal gateway tool tools toolkit suite platform
framework runtime core app application system systems software version build release
component interface protocol network security database data file files admin center
studio engine connector controller device router switch storage virtual browser mail
viewer editor player reader monitor backup remote access control http https ssl sql
для или программное обеспечение система системы сервер клиент модуль библиотека драйвер
прошивка платформа средство средства защиты информации управления приложение пакет версия
""".split())


def _words(text: str) -> list[str]:
    return [w.replace("ё", "е") for w in _WORD_RE.findall((text or "").lower())]


def _keys(text: str) -> set[str]:
    words = _words(text)
    keys = {w for w in words if len(
        w) >= MIN_WORD and not w.isdigit() and w not in _STOP}
    keys |= {a + b for a, b in zip(words, words[1:])
             if len(a + b) >= MIN_WORD + 1 and any(_content(w) for w in (a, b))}
    return keys


def _content(word: str) -> bool:
    return len(word) >= 2 and not word.isdigit() and word not in _STOP


def vendor_key(vendor: str) -> str:
    return " ".join(w for w in _words(vendor) if w not in _LEGAL)


def vendors_match(a: str, b: str) -> bool:
    if not a or not b:
        return False
    short, long_ = sorted((a, b), key=len)
    return short == long_ or f" {short} " in f" {long_} "


class ChannelIndex:

    def __init__(
        self, software: Sequence[Software], word_df_max: int = WORD_DF_MAX,
        word_limit: int = WORD_LIMIT, vendor_max: int = VENDOR_MAX,
    ) -> None:
        self._word_limit, self._vendor_max = word_limit, vendor_max
        postings: dict[str, list[int]] = {}
        for index, sw in enumerate(software):
            for key in _keys(sw.name):
                postings.setdefault(key, []).append(index)
        self._postings = {k: v for k,
                          v in postings.items() if len(v) <= word_df_max}
        self._vendors: dict[str, list[int]] = {}
        for index, sw in enumerate(software):
            key = vendor_key(sw.vendor)
            if key:
                self._vendors.setdefault(key, []).append(index)
        self._vendor_words: dict[str, set[str]] = {}
        for key in self._vendors:
            for word in key.split():
                self._vendor_words.setdefault(word, set()).add(key)

    def word(self, vendor: str, product: str) -> list[int]:
        score: dict[int, float] = {}
        for key in _keys(f"{vendor} {product}"):
            hits = self._postings.get(key)
            if not hits:
                continue
            for index in hits:
                score[index] = score.get(index, 0.0) + 1.0 / len(hits)
        ranked = sorted(score, key=lambda i: (-score[i], i))
        return ranked[: self._word_limit]

    def knows_vendor(self, vendor: str) -> bool:
        key = vendor_key(vendor)
        if not key:
            return True
        nearby = {k for word in key.split()
                  for k in self._vendor_words.get(word, ())}
        return any(vendors_match(key, k) for k in nearby)

    def vendor(self, vendor: str) -> list[int]:
        key = vendor_key(vendor)
        if not key:
            return []
        nearby = {k for word in key.split()
                  for k in self._vendor_words.get(word, ())}
        found = sorted(i for k in nearby if vendors_match(key, k)
                       for i in self._vendors[k])
        return found if 0 < len(found) <= self._vendor_max else []
