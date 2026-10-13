"""Кандидаты пары и правила авто-статусов: каналы поиска, длина списка, «уверенное НЕТ», запрет авто-ДА в строках с ОС."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

from status.core.constants import SOURCE_AUTO_SCORE, SOURCE_MANUAL, STATUS_EMPTY, STATUS_YES
from status.core.models import MatchCandidate, PairAnalysisResult, PipelineSettings, Software
from status.core.services.candidate_channels import VENDOR_MAX, WORD_LIMIT, ChannelIndex

if TYPE_CHECKING:
    from status.ports.ml_port import VectorizerPort

CHANNEL_EXTRA = WORD_LIMIT + VENDOR_MAX
OS_WORDS = re.compile(
    r"(ред\s*ос|red\s*os|astra\s*linux|астра\s*линукс|debian|ubuntu|cent\s*os"
    r"|alt\s*linux|альт\s*линукс|rosa\s*linux|linux|линукс|windows\s+server)",
    re.IGNORECASE,
)
CONFIDENT_NO_RULES = ("off", "0.35", "vendor<0.6", "vendor")


class CandidatePool:

    def __init__(self, software: Sequence[Software], channels: bool = True) -> None:
        self._software = list(software)
        self._position = {id(sw): i for i, sw in enumerate(self._software)}
        self.channels = ChannelIndex(self._software) if channels else None

    def gather(self, raw_text: str, vendor: str, product: str, vectorizer: VectorizerPort,
               settings: PipelineSettings) -> list[tuple[Software, float, str, bool]]:
        top_n, gate = settings.top_n, settings.vector_threshold
        if self.channels is None:
            found = vectorizer.search(raw_text, top_n=top_n)
            if not any(score >= gate for _, score in found):
                return []
            return [(sw, score, "", False) for sw, score in found]

        ranked = vectorizer.search(raw_text, top_n=len(self._software))
        word = set(self.channels.word(vendor, product or raw_text))
        by_vendor = set(self.channels.vendor(vendor))

        def channel(index: int) -> str:
            return "+".join(name for name, hits in (("word", word), ("vendor", by_vendor))
                            if index in hits)

        top = ranked[:top_n]
        gate_ok = any(score >= gate for _, score in top)
        pool: list[tuple[Software, float, str, bool]] = []
        taken: set[int] = set()
        for sw, score in top:
            index = self._position.get(id(sw), -1)
            taken.add(index)
            if gate_ok or channel(index):
                pool.append((sw, score, channel(index), not gate_ok))
        scores = {self._position.get(id(sw), -1): score for sw, score in ranked}
        extras = sorted((word | by_vendor) - taken, key=lambda i: (-scores.get(i, 0.0), i))
        pool += [(self._software[i], scores.get(i, 0.0), channel(i), True)
                 for i in extras[:CHANNEL_EXTRA]]
        return pool

    def knows_vendor(self, vendor: str) -> bool:
        return self.channels is None or self.channels.knows_vendor(vendor)


def cut_for_duty(candidates: list[MatchCandidate], settings: PipelineSettings
                 ) -> list[MatchCandidate]:
    size = settings.duty_list_size
    if size <= 0 or len(candidates) <= size:
        return candidates
    kept = candidates[:size]
    if settings.keep_channel_candidates:
        kept += [c for c in candidates[size:] if c.channel]
    return kept


def confident_no(vendor: str, candidates: list[MatchCandidate], settings: PipelineSettings,
                 pool: CandidatePool | None) -> bool:
    rule = settings.confident_no
    if rule == "off" or not candidates or pool is None or pool.channels is None:
        return False
    if any(c.channel for c in candidates):
        return False
    best = candidates[0].combined_score
    if rule == "0.35":
        return best < 0.35
    if rule == "vendor<0.6":
        return best < 0.6 and not pool.knows_vendor(vendor)
    if rule == "vendor":
        return not pool.knows_vendor(vendor)
    return False


def block_auto_yes_with_os(pairs: list[PairAnalysisResult], settings: PipelineSettings) -> None:
    if not settings.no_auto_yes_with_os or not any(OS_WORDS.search(p.product or "")
                                                   for p in pairs):
        return
    for pair in pairs:
        if pair.status_source != SOURCE_AUTO_SCORE:
            continue
        if pair.status == STATUS_YES:
            pair.status = STATUS_EMPTY
        pair.status_source = SOURCE_MANUAL
        if len(pair.candidates) != 1:
            pair.ppts_id = None
