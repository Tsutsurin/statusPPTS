'''Единая нормализация названий ТСУ и ППТС перед сопоставлением.'''

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen


def clean(value: str) -> str:
    return re.sub(r'\s+', ' ', value.replace('\xa0', ' ')).strip()


class NameNormalizer:
    def __init__(self, config: dict):
        self.config = config
        self.audit = []
        self.cache_path = (
            Path(config['cache_file'])
            if config.get('cache_file')
            else None
        )
        self.cache = (
            json.loads(self.cache_path.read_text(encoding='utf-8'))
            if self.cache_path and self.cache_path.exists()
            else {}
        )
        self.prompt = (
            Path(config['prompt_file']).read_text(encoding='utf-8')
            if config.get('enabled')
            else ''
        )
        self.aliases = config.get('confirmed_aliases', [])

    def _key(self, vendor, product):
        data = [
            self.config.get('url'),
            self.config.get('model'),
            self.prompt,
            vendor,
            product
        ]
        return hashlib.sha256(
            json.dumps(data, ensure_ascii=False).encode()
        ).hexdigest()

    def _request(self, batch):
        headers = {'Content-Type': 'application/json'}
        env = self.config.get('api_key_env')

        if env:
            key = os.environ.get(env)
            if not key:
                raise ValueError(f'Не задана переменная {env}')
            headers['Authorization'] = f'Bearer {key}'

        payload = {
            'model': self.config['model'],
            'temperature': 0,
            'messages': [
                {
                    'role': 'system',
                    'content': self.prompt
                },
                {
                    'role': 'user',
                    'content': json.dumps(
                        {'items': batch},
                        ensure_ascii=False
                    )
                }
            ]
        }

        if self.config.get('json_mode', True):
            payload['response_format'] = {'type': 'json_object'}

        request = Request(
            self.config['url'],
            headers=headers,
            method='POST',
            data=json.dumps(payload).encode('utf-8')
        )

        with urlopen(
            request,
            timeout=int(self.config.get('timeout_seconds', 120))
        ) as response:
            content = json.load(response)['choices'][0]['message']['content']

        items = json.loads(content).get('items')

        if not isinstance(items, list) or len(items) != len(batch):
            raise ValueError(
                'Нормализатор вернул неправильное число записей'
            )

        expected = {x['id']: x for x in batch}
        result = {}

        for item in items:
            required = {'id', 'vendor', 'product', 'decision', 'reason'}

            if not isinstance(item, dict) or set(item) != required:
                raise ValueError(
                    'Ответ должен содержать только поля нормализации'
                )

            key = item['id']

            if type(key) is not int or key not in expected or key in result:
                raise ValueError(
                    'Неизвестный или повторяющийся ID ответа'
                )

            if item['decision'] not in (
                'normalized',
                'unchanged',
                'uncertain'
            ):
                raise ValueError(
                    'Недопустимое решение нормализатора'
                )

            if any(
                not isinstance(item[field], str)
                for field in ('vendor', 'product', 'reason')
            ):
                raise ValueError(
                    'Названия и обоснование должны быть строками'
                )

            if (
                not item['product'].strip()
                or max(len(item['vendor']), len(item['product'])) > 1000
            ):
                raise ValueError(
                    'Пустое или слишком длинное название'
                )

            before = re.findall(
                r'\d+(?:\.\d+)*',
                expected[key]['product']
            )
            after = re.findall(
                r'\d+(?:\.\d+)*',
                item['product']
            )

            if before != after:
                raise ValueError(
                    'ИИ изменил числовые маркеры продукта'
                )

            if item['decision'] != 'normalized':
                item['vendor'] = expected[key]['vendor']
                item['product'] = expected[key]['product']

            result[key] = item

        return result

    def names(self, pairs):
        unique = list(
            dict.fromkeys((clean(v), clean(p)) for v, p in pairs)
        )
        resolved = {}
        pending = []

        for vendor, product in unique:
            alias = next(
                (
                    item
                    for item in self.aliases
                    if (
                        clean(item['vendor']).casefold(),
                        clean(item['product']).casefold()
                    ) == (
                        vendor.casefold(),
                        product.casefold()
                    )
                ),
                None
            )

            if alias:
                decision = {
                    'vendor': clean(alias['canonical_vendor']),
                    'product': clean(alias['canonical_product']),
                    'decision': 'confirmed_alias',
                    'reason': 'Подтверждённое соответствие'
                }

            elif (
                self.config.get('enabled')
                and self._key(vendor, product) in self.cache
            ):
                decision = self.cache[self._key(vendor, product)]

            elif self.config.get('enabled') and product:
                pending.append((vendor, product))
                continue

            else:
                decision = {
                    'vendor': vendor,
                    'product': product,
                    'decision': 'unchanged',
                    'reason': 'Очистка пробелов'
                }

            resolved[(vendor, product)] = decision

        size = int(self.config.get('batch_size', 20))

        if size < 1:
            raise ValueError('batch_size должен быть больше нуля')

        for offset in range(0, len(pending), size):
            chunk = pending[offset:offset + size]
            batch = [
                {
                    'id': index,
                    'vendor': vendor,
                    'product': product
                }
                for index, (vendor, product) in enumerate(chunk)
            ]

            answer = self._request(batch)

            for index, (vendor, product) in enumerate(chunk):
                decision = {
                    key: value
                    for key, value in answer[index].items()
                    if key != 'id'
                }

                resolved[(vendor, product)] = decision

                if decision['decision'] != 'uncertain':
                    self.cache[self._key(vendor, product)] = decision

        self.audit = [
            {
                'vendor_raw': vendor,
                'product_raw': product,
                **decision
            }
            for (vendor, product), decision in resolved.items()
        ]

        if self.cache_path:
            self.cache_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )
            temporary = self.cache_path.with_suffix('.tmp')
            temporary.write_text(
                json.dumps(
                    self.cache,
                    ensure_ascii=False,
                    indent=2
                ),
                encoding='utf-8'
            )
            os.replace(temporary, self.cache_path)

        return resolved

    def normalize(self, vulnerabilities, software):
        from status.core.services.matching_worker import _ensure_vuln_pairs

        vulnerabilities = deepcopy(vulnerabilities)
        software = deepcopy(software)

        for vuln in vulnerabilities:
            vuln.original_product = (
                vuln.original_product or vuln.product
            )
            _ensure_vuln_pairs(vuln)

        labels = [
            (pair.vendor, pair.product)
            for vuln in vulnerabilities
            for pair in vuln.pairs
        ]
        labels += [
            (item.vendor, item.name)
            for item in software
        ]

        resolved = self.names(labels)

        for vuln in vulnerabilities:
            for pair in vuln.pairs:
                decision = resolved[
                    (clean(pair.vendor), clean(pair.product))
                ]

                pair.vendor = decision['vendor']
                pair.product = decision['product']
                pair.raw_text = ' '.join(
                    part
                    for part in (pair.vendor, pair.product)
                    if part
                )

            if vuln.pairs:
                vuln.vendor = vuln.pairs[0].vendor
                vuln.product = '; '.join(
                    pair.product for pair in vuln.pairs
                )
                vuln.raw_text = '; '.join(
                    pair.raw_text for pair in vuln.pairs
                )

        for item in software:
            item.original_name = item.name
            item.original_vendor = item.vendor

            decision = resolved[
                (clean(item.vendor), clean(item.name))
            ]

            item.vendor = decision['vendor']
            item.name = decision['product']

        return vulnerabilities, software