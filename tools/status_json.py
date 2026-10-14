"""STATUS без GUI: таблицы ТСУ и ППТС преобразуются в JSON."""

from __future__ import annotations

import argparse
from collections import Counter
import dataclasses
import datetime
import json
import logging
from pathlib import Path
import shutil
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from status.core.models import AnalysisResult, MatchCandidate
    from status.core.models import PipelineSettings

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger('status_json')

MODES: dict[str, dict[str, object]] = {
    'llm': {
        'vector_threshold': 0.25,
        'candidate_mode': 'all',
        'duty_list_size': 0,
        'candidate_channels': True,
        'auto_match_threshold': 0.85,
        'auto_match_margin': 0.1,
        'no_auto_yes_with_os': True,
        'confident_no': '0.35',
        'hide_weak_in_auto_no': False,
    },
    'recall': {
        'vector_threshold': 0.25,
        'candidate_mode': 'all',
        'duty_list_size': 0,
        'candidate_channels': False,
        'no_auto_yes_with_os': False,
        'confident_no': 'off',
        'hide_weak_in_auto_no': False,
    },
    'app': {},
}


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='STATUS без веба: ТСУ → JSON с кандидатами'
    )
    parser.add_argument(
        '--tsu', action='append', required=True,
        help='Файл ТСУ; параметр можно повторять',
    )
    parser.add_argument('--ppts-local', default=None)
    parser.add_argument('--ppts-general', default=None)
    parser.add_argument(
        '--kb', default=None, help='knowledge.db; читается копия',
    )
    parser.add_argument(
        '--journal', action='append', default=None,
        help='Журнал для пометки ПОВТОР; параметр можно повторять',
    )
    parser.add_argument(
        '--app-config', default=None,
        help='matcher_config.json приложения',
    )
    parser.add_argument('--mode', choices=sorted(MODES), default='llm')
    parser.add_argument(
        '--top-n', type=int, default=None,
        help='Количество кандидатов на пару; по умолчанию 10',
    )
    parser.add_argument('--out', default='status_result.json')
    parser.add_argument(
        '--normalize-config',
        help='JSON конфигурации нормализации названий',
    )
    return parser.parse_args()


def load_settings(
    app_config: str | None,
    mode: str,
    top_n: int | None,
) -> PipelineSettings:
    from status.core.models import PipelineSettings

    settings = PipelineSettings()

    if app_config:
        data = json.loads(Path(app_config).read_text(encoding='utf-8'))
        known = {field.name for field in dataclasses.fields(PipelineSettings)}
        settings = PipelineSettings(
            **{key: value for key, value in data.items() if key in known}
        )

    overrides = dict(MODES[mode])

    if top_n is not None:
        if top_n < 1:
            raise ValueError('--top-n должен быть больше нуля')
        overrides['top_n'] = top_n

    return dataclasses.replace(settings, **overrides)


def _candidate(candidate: MatchCandidate) -> dict:
    software = candidate.software

    return {
        'id': software.id,
        'name': software.name,
        'vendor': software.vendor,
        'ppts': software.source,
        'score': round(candidate.combined_score, 4),
        'vector': round(candidate.vector_score, 4),
        'fuzzy': round(candidate.fuzzy_score, 2),
        'exact': round(candidate.exact_score, 2),
        'channel': candidate.channel,
        'channel_only': candidate.channel_only,
        'name_raw': software.original_name or software.name,
        'vendor_raw': software.original_vendor or software.vendor,
    }


def _source(url: str) -> str:
    value = (url or '').lower()

    if 'bdu.fstec' in value:
        return 'fstek'

    return 'other' if value else 'unknown'


def to_dict(result: AnalysisResult) -> dict:
    vulnerability = result.vulnerability

    return {
        'cve': vulnerability.cve_id,
        'source_url': vulnerability.source_url,
        'source': _source(vulnerability.source_url),
        'cvss': vulnerability.cvss,
        'product_raw': (
            vulnerability.original_product or vulnerability.product
        ),
        'status': result.status,
        'status_source': result.status_source,
        'ppts_id': result.ppts_id,
        'journal': [
            {
                'status': entry.status,
                'ppts_id': entry.ppts_id,
                'product': entry.product,
                'file': entry.source_file,
            }
            for entry in result.journal_matches
        ],
        'pairs': [
            {
                'vendor': pair.vendor,
                'product': pair.product,
                'versions': pair.versions,
                'status': pair.status,
                'status_source': pair.status_source,
                'ppts_id': pair.ppts_id,
                'candidates': [
                    _candidate(candidate) for candidate in pair.candidates
                ],
            }
            for pair in result.pair_results
        ],
    }


def run(args: argparse.Namespace) -> dict:
    from status import __version__
    from status.adapters.io.excel_reader_adapter import ExcelReaderAdapter
    from status.adapters.matchers.rapidfuzz_adapter import RapidFuzzAdapter
    from status.adapters.ml.sentence_transformer_adapter import (
        SentenceTransformerAdapter,
    )
    from status.core.services.matching_service import MatchingService

    settings = load_settings(args.app_config, args.mode, args.top_n)
    reader = ExcelReaderAdapter()

    vulnerabilities = [
        vulnerability
        for path in args.tsu
        for vulnerability in reader.read_tsu(path)
    ]

    software = []

    if args.ppts_local:
        software += reader.read_ppts(args.ppts_local, source='local_ppts')

    if args.ppts_general:
        software += reader.read_ppts(args.ppts_general, source='general_ppts')

    journal = [
        entry
        for path in (args.journal or [])
        for entry in reader.read_journal(path, Path(path).stem)
    ]

    normalization = []

    if getattr(args, 'normalize_config', None):
        from status.adapters.name_normalizer import NameNormalizer

        config_path = Path(args.normalize_config).resolve()
        config = json.loads(config_path.read_text(encoding='utf-8-sig'))

        for key in ('prompt_file', 'cache_file'):
            if config.get(key):
                config[key] = str((config_path.parent / config[key]).resolve())

        normalizer = NameNormalizer(config)
        vulnerabilities, software = normalizer.normalize(
            vulnerabilities, software,
        )
        normalization = normalizer.audit

    repository = None
    connection = None
    workdir = None

    try:
        if args.kb:
            from status.adapters.db.sqlite_repository import SqliteRepository
            from status.adapters.db.sqlite_schema import init_db

            workdir = Path(tempfile.mkdtemp(prefix='status_json_'))
            shutil.copy2(args.kb, workdir / 'knowledge.db')
            connection = init_db(workdir / 'knowledge.db')
            repository = SqliteRepository(connection)
            settings = dataclasses.replace(settings, use_knowledge_base=True)

        service = MatchingService(
            settings,
            SentenceTransformerAdapter(),
            RapidFuzzAdapter(
                threshold=settings.fuzzy_threshold,
                min_word_length=settings.min_word_length,
            ),
            repository,
        )

        results = service.run(vulnerabilities, software, journal or None)

    finally:
        if connection is not None:
            connection.close()

        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)

    settings_fields = (
        'top_n', 'vector_threshold', 'candidate_mode', 'min_word_length',
        'weight_vector', 'weight_fuzzy', 'weight_exact',
        'auto_match_threshold', 'auto_match_margin', 'candidate_channels',
        'duty_list_size', 'no_auto_yes_with_os', 'confident_no',
        'use_knowledge_base',
    )

    return {
        'meta': {
            'generated_at': datetime.datetime.now().isoformat(
                timespec='seconds'
            ),
            'status_version': __version__,
            'mode': args.mode,
            'settings': {
                key: getattr(settings, key) for key in settings_fields
            },
            'inputs': {
                'tsu': [Path(path).name for path in args.tsu],
                'ppts_positions': len(software),
                'journal_entries': len(journal),
                'kb': bool(args.kb),
            },
            'counts': {
                'vulnerabilities': len(results),
                'pairs': sum(len(result.pair_results) for result in results),
                'statuses': dict(Counter(
                    result.status or 'пусто' for result in results
                )),
            },
        },
        'items': [to_dict(result) for result in results],
        'normalization': normalization,
    }


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if callable(reconfigure):
            reconfigure(errors='replace')

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(message)s',
        datefmt='%H:%M:%S',
    )
    logging.getLogger('status').setLevel(logging.WARNING)

    args = _args()

    paths = [
        *args.tsu,
        args.ppts_local,
        args.ppts_general,
        args.kb,
        args.app_config,
        args.normalize_config,
        *(args.journal or []),
    ]

    for path in paths:
        if path and not Path(path).is_file():
            logger.error('Не найден файл: %s', path)
            return 2

    if not args.ppts_local and not args.ppts_general:
        logger.error(
            'Нужен хотя бы один ППТС: --ppts-local или --ppts-general'
        )
        return 2

    try:
        document = run(args)
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )

    except Exception:
        logger.exception('Обработка остановлена')
        return 1

    counts = document['meta']['counts']

    logger.info(
        'Готово: %d уязвимостей, %d пар → %s',
        counts['vulnerabilities'], counts['pairs'], args.out,
    )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())