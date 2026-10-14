from argparse import Namespace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from openpyxl import Workbook
from openpyxl.worksheet.worksheet import Worksheet

from status.adapters.name_normalizer import NameNormalizer
from status.core.models import (
    Software,
    Vulnerability,
    VulnerabilityPair
)
from tools.status_json import run


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        prompt = self.root / 'prompt.txt'
        prompt.write_text('test', encoding='utf-8')

        self.config = {
            'enabled': True,
            'url': 'https://test/api',
            'model': 'test',
            'prompt_file': str(prompt),
            'cache_file': str(self.root / 'cache.json')
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_aliases_normalize_both_sources_without_mutating_originals(self):
        config = {
            'enabled': False,
            'confirmed_aliases': [
                {
                    'vendor': 'Red Hat Inc.',
                    'product': 'RHEL',
                    'canonical_vendor': 'Red Hat',
                    'canonical_product': 'Red Hat Enterprise Linux'
                }
            ]
        }

        pair = VulnerabilityPair(
            'Red Hat Inc.',
            'RHEL',
            ['от 8 до 9 включительно']
        )
        vuln = Vulnerability(
            'CVE-2026-10001',
            pair.vendor,
            pair.product,
            '',
            '',
            cvss='8.8',
            pairs=[pair]
        )
        software = Software(
            '1',
            'RHEL',
            'Red Hat Inc.',
            'ppts'
        )

        normalizer = NameNormalizer(config)
        vulns, products = normalizer.normalize(
            [vuln],
            [software]
        )

        self.assertEqual(
            vulns[0].pairs[0].product,
            products[0].name
        )
        self.assertEqual(
            vulns[0].pairs[0].versions,
            ['от 8 до 9 включительно']
        )
        self.assertEqual(vulns[0].cvss, '8.8')
        self.assertEqual(vuln.product, 'RHEL')
        self.assertEqual(products[0].original_name, 'RHEL')

    def answer(
        self,
        decision='normalized',
        product='Viewer 9',
        extra=None
    ):
        item = {
            'id': 0,
            'vendor': 'Acme',
            'product': product,
            'decision': decision,
            'reason': 'test'
        }

        if extra:
            item.update(extra)

        content = json.dumps({'items': [item]})

        class Response:
            def __enter__(self):
                import io

                return io.StringIO(
                    json.dumps({
                        'choices': [
                            {
                                'message': {
                                    'content': content
                                }
                            }
                        ]
                    })
                )

            def __exit__(self, *args):
                pass

        return Response()

    def test_uncertain_keeps_source_names(self):
        normalizer = NameNormalizer(self.config)

        with patch(
            'status.adapters.name_normalizer.urlopen',
            return_value=self.answer('uncertain')
        ):
            result = normalizer.names([
                ('Acme Ltd.', 'viewer 9')
            ])

        self.assertEqual(
            result[('Acme Ltd.', 'viewer 9')]['vendor'],
            'Acme Ltd.'
        )
        self.assertEqual(
            result[('Acme Ltd.', 'viewer 9')]['product'],
            'viewer 9'
        )

    def test_number_changes_are_rejected(self):
        with patch(
            'status.adapters.name_normalizer.urlopen',
            return_value=self.answer(product='Viewer 10')
        ):
            with self.assertRaises(ValueError):
                NameNormalizer(self.config).names([
                    ('Acme', 'Viewer 9')
                ])

    def test_status_fields_are_rejected(self):
        with patch(
            'status.adapters.name_normalizer.urlopen',
            return_value=self.answer(extra={'status': 'ДА'})
        ):
            with self.assertRaises(ValueError):
                NameNormalizer(self.config).names([
                    ('Acme', 'Viewer 9')
                ])

    def test_duplicates_and_cache_use_one_request(self):
        with patch(
            'status.adapters.name_normalizer.urlopen',
            return_value=self.answer()
        ) as call:
            NameNormalizer(self.config).names([
                ('Acme', 'Viewer 9'),
                ('Acme', 'Viewer 9')
            ])

            self.assertEqual(call.call_count, 1)

        with patch(
            'status.adapters.name_normalizer.urlopen'
        ) as call:
            NameNormalizer(self.config).names([
                ('Acme', 'Viewer 9')
            ])

            call.assert_not_called()

    def test_full_status_run_with_local_normalization(self):
        inputs = [
            (
                'tsu.xlsx',
                ['CVE', 'CVSS', 'Продукт', 'Источник'],
                [
                    'CVE-2026-10001',
                    '8.8',
                    'Acme - Viewer - 9',
                    'https://bdu.fstec.ru/vul/2026-00001'
                ]
            ),
            (
                'ppts.xlsx',
                ['ID ППТС', 'Название ПТС', 'Вендор'],
                ['1', 'Viewer', 'Acme']
            )
        ]

        for filename, headers, row in inputs:
            workbook = Workbook()
            worksheet = workbook.active

            if not isinstance(worksheet, Worksheet):
                raise TypeError('Активный лист должен быть Worksheet')

            worksheet.append(headers)
            worksheet.append(row)
            workbook.save(self.root / filename)
            workbook.close()

        config_path = self.root / 'config.json'
        config_path.write_text(
            '{"enabled": false}',
            encoding='utf-8'
        )

        args = Namespace(
            tsu=[str(self.root / 'tsu.xlsx')],
            ppts_local=None,
            ppts_general=str(self.root / 'ppts.xlsx'),
            journal=None,
            kb=None,
            app_config=None,
            mode='llm',
            top_n=10,
            normalize_config=str(config_path)
        )

        result = run(args)

        self.assertEqual(
            result['items'][0]['cvss'],
            '8.8'
        )
        self.assertEqual(
            result['items'][0]['pairs'][0]['versions'],
            ['9']
        )
        self.assertTrue(result['normalization'])

        args.normalize_config = None
        baseline = run(args)

        self.assertEqual(
            result['items'][0]['status'],
            baseline['items'][0]['status']
        )


if __name__ == '__main__':
    unittest.main()