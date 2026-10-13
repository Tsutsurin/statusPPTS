"""STATUS без веба: файлы ТСУ на входе, JSON с кандидатами и статусами каждой пары на выходе."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import logging
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from status import __version__
from status.adapters.io.excel_reader_adapter import ExcelReaderAdapter
from status.core.models import AnalysisResult, MatchCandidate, PipelineSettings

logger = logging.getLogger("status_json")

MODES: dict[str, dict[str, object]] = {
    "llm": {"vector_threshold": 0.25, "candidate_mode": "all", "duty_list_size": 0,
            "candidate_channels": True, "auto_match_threshold": 0.85, "auto_match_margin": 0.1,
            "no_auto_yes_with_os": True, "confident_no": "0.35", "hide_weak_in_auto_no": False},
    "recall": {"vector_threshold": 0.25, "candidate_mode": "all", "duty_list_size": 0,
               "candidate_channels": False, "no_auto_yes_with_os": False, "confident_no": "off",
               "hide_weak_in_auto_no": False},
    "app": {},
}


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="STATUS без веба: ТСУ → JSON с кандидатами")
    parser.add_argument("--tsu", action="append", required=True, help="файл ТСУ (можно несколько)")
    parser.add_argument("--ppts-local", default=None)
    parser.add_argument("--ppts-general", default=None)
    parser.add_argument("--kb", default=None, help="knowledge.db (читается копия)")
    parser.add_argument("--journal", action="append", default=None,
                        help="журнал для пометки ПОВТОР (можно несколько)")
    parser.add_argument("--app-config", default=None, help="matcher_config.json приложения")
    parser.add_argument("--mode", choices=sorted(MODES), default="llm")
    parser.add_argument("--top-n", type=int, default=None, help="кандидатов на пару (по умолч. 10)")
    parser.add_argument("--out", default="status_result.json")
    return parser.parse_args()


def load_settings(app_config: str | None, mode: str, top_n: int | None) -> PipelineSettings:
    settings = PipelineSettings()
    if app_config:
        data = json.loads(Path(app_config).read_text(encoding="utf-8"))
        known = {f.name for f in dataclasses.fields(PipelineSettings)}
        settings = PipelineSettings(**{k: v for k, v in data.items() if k in known})
    overrides = dict(MODES[mode])
    if top_n:
        overrides["top_n"] = top_n
    return dataclasses.replace(settings, **overrides)


def _candidate(c: MatchCandidate) -> dict:
    return {"id": c.software.id, "name": c.software.name, "vendor": c.software.vendor,
            "ppts": c.software.source, "score": round(c.combined_score, 4),
            "vector": round(c.vector_score, 4), "fuzzy": round(c.fuzzy_score, 2),
            "exact": round(c.exact_score, 2), "channel": c.channel,
            "channel_only": c.channel_only}


def _source(url: str) -> str:
    low = (url or "").lower()
    return "fstek" if "bdu.fstec" in low else ("unknown" if not low else "other")


def to_dict(result: AnalysisResult) -> dict:
    vuln = result.vulnerability
    return {
        "cve": vuln.cve_id, "source_url": vuln.source_url, "source": _source(vuln.source_url),
        "product_raw": vuln.original_product or vuln.product, "status": result.status,
        "status_source": result.status_source, "ppts_id": result.ppts_id,
        "journal": [{"status": j.status, "ppts_id": j.ppts_id, "product": j.product,
                     "file": j.source_file} for j in result.journal_matches],
        "pairs": [{"vendor": p.vendor, "product": p.product, "versions": p.versions,
                   "status": p.status, "status_source": p.status_source, "ppts_id": p.ppts_id,
                   "candidates": [_candidate(c) for c in p.candidates]}
                  for p in result.pair_results],
    }


def run(args: argparse.Namespace) -> dict:
    from status.adapters.matchers.rapidfuzz_adapter import RapidFuzzAdapter
    from status.adapters.ml.sentence_transformer_adapter import SentenceTransformerAdapter
    from status.core.services.matching_service import MatchingService

    settings = load_settings(args.app_config, args.mode, args.top_n)
    reader = ExcelReaderAdapter()
    vulns = [v for path in args.tsu for v in reader.read_tsu(path)]
    software = []
    if args.ppts_local:
        software += reader.read_ppts(args.ppts_local, source="local_ppts")
    if args.ppts_general:
        software += reader.read_ppts(args.ppts_general, source="general_ppts")
    journal = [e for path in args.journal or [] for e in reader.read_journal(path, Path(path).stem)]

    repo, conn, workdir = None, None, None
    if args.kb:
        from status.adapters.db.sqlite_repository import SqliteRepository
        from status.adapters.db.sqlite_schema import init_db

        workdir = Path(tempfile.mkdtemp(prefix="status_json_"))
        shutil.copy2(args.kb, workdir / "knowledge.db")
        conn = init_db(workdir / "knowledge.db")
        repo = SqliteRepository(conn)
        settings = dataclasses.replace(settings, use_knowledge_base=True)
    try:
        service = MatchingService(
            settings, SentenceTransformerAdapter(),
            RapidFuzzAdapter(threshold=settings.fuzzy_threshold,
                             min_word_length=settings.min_word_length), repo)
        results = service.run(vulns, software, journal or None)
    finally:
        if conn is not None:
            conn.close()
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)

    return {
        "meta": {
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "status_version": __version__, "mode": args.mode,
            "settings": {k: getattr(settings, k) for k in (
                "top_n", "vector_threshold", "candidate_mode", "min_word_length",
                "weight_vector", "weight_fuzzy", "weight_exact", "auto_match_threshold",
                "auto_match_margin", "candidate_channels", "duty_list_size",
                "no_auto_yes_with_os", "confident_no", "use_knowledge_base")},
            "inputs": {"tsu": [Path(p).name for p in args.tsu], "ppts_positions": len(software),
                       "journal_entries": len(journal), "kb": bool(args.kb)},
            "counts": {"vulnerabilities": len(results),
                       "pairs": sum(len(r.pair_results) for r in results),
                       "statuses": dict(Counter(r.status or "пусто" for r in results))},
        },
        "items": [to_dict(r) for r in results],
    }


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("status").setLevel(logging.WARNING)
    args = _args()
    for path in [*args.tsu, args.ppts_local, args.ppts_general, args.kb, args.app_config,
                 *(args.journal or [])]:
        if path and not Path(path).is_file():
            logger.error("Не найден файл: %s", path)
            return 2
    if not args.ppts_local and not args.ppts_general:
        logger.error("Нужен хотя бы один ППТС: --ppts-local или --ppts-general")
        return 2
    document = run(args)
    Path(args.out).write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    counts = document["meta"]["counts"]
    logger.info("Готово: %d уязвимостей, %d пар → %s", counts["vulnerabilities"], counts["pairs"],
                args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
