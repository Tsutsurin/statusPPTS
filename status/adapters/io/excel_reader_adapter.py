"""Чтение ТСУ, ППТС и журнала публикаций из Excel и CSV."""

from __future__ import annotations
from status.core.services.normalizer import parse_fstek_pairs

import copy
import logging
from pathlib import Path

from status.core.models import JournalEntry, PptsColumnMapping, Software, Vulnerability, VulnerabilityPair
from status.ports.reader_port import DataReaderPort
from status.adapters.io.reader_helpers import (
    ReaderError,
    TSU_CVE_KEYS,
    TSU_CVSS_KEYS,
    TSU_PRODUCT_KEYS,
    TSU_SOURCE_KEYS,
    JOURNAL_CVE_KEYS,
    JOURNAL_STATUS_KEYS,
    JOURNAL_PPTS_ID_KEYS,
    JOURNAL_RESPONSIBLE_KEYS,
    JOURNAL_PRODUCT_KEYS,
    JOURNAL_COL_CVE,
    JOURNAL_COL_STATUS,
    JOURNAL_COL_PPTS_ID,
    JOURNAL_COL_RESPONSIBLE,
    JOURNAL_COL_PRODUCT,
    JOURNAL_SHEET_NAME,
    _read_rows,
    _find_column,
    _safe_get,
    _split_vendor_product,
    _clean_header,
    _header_label,
    detect_ppts_header_row,
    detect_ppts_columns,
    auto_detect_ppts_mapping,
    split_cve_cell,
)

logger = logging.getLogger(__name__)


class ExcelReaderAdapter(DataReaderPort):

    def read_tsu(self, file_path: str | Path) -> list[Vulnerability]:
        path = Path(file_path)
        if not path.exists():
            raise ReaderError(f"File not found: {path}")

        try:
            rows = _read_rows(path)
        except ReaderError:
            raise
        except Exception as exc:
            raise ReaderError(f"Failed to read {path.name}: {exc}") from exc

        if len(rows) < 2:
            raise ReaderError(f"File {path.name} has no data rows")

        headers = [str(h) for h in rows[0]]
        col_cve = _find_column(headers, TSU_CVE_KEYS)
        col_cvss = _find_column(headers, TSU_CVSS_KEYS)
        col_product = _find_column(headers, TSU_PRODUCT_KEYS)
        col_source = _find_column(headers, TSU_SOURCE_KEYS)

        if col_product is None:
            raise ReaderError(
                f"Cannot find product column in {path.name}. "
                f"Headers: {[_clean_header(h) for h in headers]}"
            )

        vulnerabilities: list[Vulnerability] = []
        for row_idx, row in enumerate(rows[1:], start=2):
            combined_product = _safe_get(row, col_product)
            if not combined_product:
                logger.debug("Skipping row %d: empty product", row_idx)
                continue

            cves = split_cve_cell(_safe_get(row, col_cve))
            cvss = _safe_get(row, col_cvss)
            source_url = _safe_get(row, col_source)

            pairs = []
            parsed_groups = parse_fstek_pairs(combined_product)
            for v_vend, v_prod, v_vers in parsed_groups:
                raw = " ".join(part for part in (v_vend, v_prod) if part)
                pairs.append(
                    VulnerabilityPair(
                        vendor=v_vend,
                        product=v_prod,
                        versions=v_vers,
                        raw_text=raw,
                    )
                )

            if pairs:
                first_pair = pairs[0]
                vendor = first_pair.vendor
                is_fstek = (combined_product.count(
                    " - ") >= 2) or ("," in combined_product and " - " in combined_product)
                if is_fstek:
                    product = combined_product
                else:
                    product = first_pair.product
                raw_text = first_pair.raw_text
            else:
                vendor, product = _split_vendor_product(combined_product)
                raw_text = " ".join(part for part in (vendor, product) if part)

            for index, cve in enumerate(cves):
                vulnerabilities.append(
                    Vulnerability(
                        cve_id=cve,
                        vendor=vendor,
                        product=product,
                        version="",
                        raw_text=raw_text,
                        cvss=cvss,
                        source_url=source_url,
                        original_product=combined_product,
                        pairs=pairs if index == 0 else copy.deepcopy(pairs),
                    )
                )

        logger.info("Read %d vulnerabilities from %s",
                    len(vulnerabilities), path.name)
        return vulnerabilities

    def read_ppts(
        self,
        file_path: str | Path,
        source: str = "local_ppts",
        mapping: PptsColumnMapping | None = None,
    ) -> list[Software]:
        path = Path(file_path)
        if not path.exists():
            raise ReaderError(f"File not found: {path}")

        try:
            rows = _read_rows(path)
        except ReaderError:
            raise
        except Exception as exc:
            raise ReaderError(f"Failed to read {path.name}: {exc}") from exc

        if len(rows) < 2:
            raise ReaderError(f"File {path.name} has no data rows")

        header_row = detect_ppts_header_row(rows)
        header_row = max(0, min(header_row, len(rows) - 1))
        headers = [str(h) for h in rows[header_row]]
        found_nr = bool(headers) and (
            _header_label(headers[0]) == "Nr." or str(
                headers[0]).strip().startswith("Nr.")
        )

        if mapping is not None and mapping.col_name is not None:
            col_id = mapping.col_id
            col_name = mapping.col_name
            col_vendor = mapping.col_vendor
        else:
            detected = auto_detect_ppts_mapping(path)
            col_id, col_name, col_vendor = detected.col_id, detected.col_name, detected.col_vendor
            header_row = detected.header_row
            headers = [str(h) for h in rows[header_row]]
            if col_name is None:
                col_id, col_name, col_vendor = detect_ppts_columns(
                    headers, allow_fallback=found_nr)

        if col_name is None:
            raise ReaderError(
                f"Cannot find name column in {path.name}. "
                f"Headers: {[_header_label(h) for h in headers]}"
            )

        software_list: list[Software] = []
        for row_idx, row in enumerate(rows[header_row + 1:], start=header_row + 2):
            name = _safe_get(row, col_name)
            vendor = _safe_get(row, col_vendor)
            sw_id = _safe_get(row, col_id) or str(row_idx - 1)

            if not name and not vendor:
                logger.debug("Skipping row %d: empty name and vendor", row_idx)
                continue

            display_name = name if name else vendor

            software_list.append(
                Software(id=sw_id, name=display_name,
                         vendor=vendor, source=source)
            )

        logger.info("Read %d software entries from %s",
                    len(software_list), path.name)
        return software_list

    def read_journal(
        self,
        file_path: str | Path,
        source_file: str = "",
    ) -> list[JournalEntry]:
        path = Path(file_path)
        if not path.exists():
            raise ReaderError(f"File not found: {path}")

        try:
            rows = _read_rows(
                path, sheet_name=JOURNAL_SHEET_NAME, require_sheet=True)
        except ReaderError:
            raise
        except Exception as exc:
            raise ReaderError(f"Failed to read {path.name}: {exc}") from exc

        if len(rows) < 2:
            raise ReaderError(f"File {path.name} has no data rows")

        headers = [str(h) for h in rows[0]]
        col_cve = _find_column(headers, JOURNAL_CVE_KEYS)
        col_status = _find_column(headers, JOURNAL_STATUS_KEYS)
        col_ppts = _find_column(headers, JOURNAL_PPTS_ID_KEYS)
        col_resp = _find_column(headers, JOURNAL_RESPONSIBLE_KEYS)
        col_product = _find_column(headers, JOURNAL_PRODUCT_KEYS)

        if col_cve is None:
            col_cve = JOURNAL_COL_CVE
        if col_status is None:
            col_status = JOURNAL_COL_STATUS
        if col_ppts is None:
            col_ppts = JOURNAL_COL_PPTS_ID
        if col_resp is None:
            col_resp = JOURNAL_COL_RESPONSIBLE
        if col_product is None:
            col_product = JOURNAL_COL_PRODUCT

        entries: list[JournalEntry] = []
        for row in rows[1:]:
            cve = _safe_get(row, col_cve)
            if not cve:
                continue

            status_val = _safe_get(row, col_status)
            status = ""
            if status_val:
                status = status_val.strip().upper()
                if status == "LINUX":
                    status = "ЛИНУКС"
                elif status == "CONDITIONAL":
                    status = "УСЛОВНО"
                elif status == "REPEAT":
                    status = "ПОВТОР"
                elif status == "YES":
                    status = "ДА"
                elif status == "NO":
                    status = "НЕТ"

            ppts_id = _safe_get(row, col_ppts)
            responsible = _safe_get(row, col_resp)
            product = _safe_get(row, col_product)

            entries.append(
                JournalEntry(
                    cve_id=cve,
                    status=status,
                    ppts_id=ppts_id,
                    responsible=responsible,
                    product=product,
                    source_file=source_file,
                )
            )

        logger.info("Read %d journal entries from %s", len(entries), path.name)
        return entries

    def read_journal_source_urls(self, file_path: str | Path) -> set[str]:
        path = Path(file_path)
        if not path.exists():
            return set()
        try:
            rows = _read_rows(
                path, sheet_name=JOURNAL_SHEET_NAME, require_sheet=False)
            if len(rows) < 2:
                return set()
            col_source = _find_column([str(h)
                                      for h in rows[0]], TSU_SOURCE_KEYS)
            if col_source is None:
                col_source = 9
            urls = set()
            for row in rows[1:]:
                val = _safe_get(row, col_source)
                if val:
                    val_str = str(val).strip()
                    if val_str:
                        urls.add(val_str)
            return urls
        except Exception:
            logger.exception(
                "Failed to read source URLs from journal %s", path.name)
            return set()
