"""База знаний в SQLite: чтение правил и учёт их срабатываний."""

from __future__ import annotations

import logging
import sqlite3

from status.core.models import KnowledgeBaseRule, ScriptConfig
from status.ports.db_port import RuleRepositoryPort, ScriptConfigPort

logger = logging.getLogger(__name__)


def _row_to_rule(row: sqlite3.Row) -> KnowledgeBaseRule:
    return KnowledgeBaseRule(
        id=row["id"],
        pattern=row["pattern"],
        match_type=row["match_type"],
        vendor_pattern=row["vendor_pattern"] if "vendor_pattern" in row.keys(
        ) else "",
        vendor_match_type=row["vendor_match_type"] if "vendor_match_type" in row.keys(
        ) else "contains",
        status=row["status"],
        ppts_id=row["ppts_id"],
        vector_threshold=row["vector_threshold"],
        comment=row["comment"],
        created_at=row["created_at"],
        last_matched_at=row["last_matched_at"],
        match_count=row["match_count"],
    )


def _row_to_script_config(row: sqlite3.Row) -> ScriptConfig:
    return ScriptConfig(
        id=row["id"],
        script_path=row["script_path"],
        condition=row["condition"],
        priority=row["priority"],
        enabled=bool(row["enabled"]),
    )


class SqliteRepository(RuleRepositoryPort, ScriptConfigPort):

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get_all_rules(self) -> list[KnowledgeBaseRule]:
        cursor = self._conn.execute("SELECT * FROM rules ORDER BY id")
        return [_row_to_rule(row) for row in cursor.fetchall()]

    def get_rule_by_id(self, rule_id: int) -> KnowledgeBaseRule | None:
        cursor = self._conn.execute(
            "SELECT * FROM rules WHERE id = ?", (rule_id,))
        row = cursor.fetchone()
        return _row_to_rule(row) if row else None

    def search_rules(
        self,
        pattern: str | None = None,
        match_type: str | None = None,
        status: str | None = None,
    ) -> list[KnowledgeBaseRule]:
        clauses: list[str] = []
        params: list[str] = []

        if pattern is not None:
            clauses.append("(pattern LIKE ? OR vendor_pattern LIKE ?)")
            params.append(f"%{pattern}%")
            params.append(f"%{pattern}%")
        if match_type is not None:
            clauses.append("match_type = ?")
            params.append(match_type)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM rules{where} ORDER BY id"
        cursor = self._conn.execute(query, params)
        return [_row_to_rule(row) for row in cursor.fetchall()]

    def create_rule(self, rule: KnowledgeBaseRule) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO rules (pattern, match_type, vendor_pattern, vendor_match_type,
                               status, ppts_id, vector_threshold, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.pattern,
                rule.match_type,
                rule.vendor_pattern,
                rule.vendor_match_type,
                rule.status,
                rule.ppts_id,
                rule.vector_threshold,
                rule.comment,
            ),
        )
        self._conn.commit()
        rule_id = cursor.lastrowid
        logger.info("Created rule id=%d pattern=%r", rule_id, rule.pattern)
        return rule_id

    def update_rule(self, rule: KnowledgeBaseRule) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE rules
            SET pattern = ?, match_type = ?, vendor_pattern = ?, vendor_match_type = ?,
                status = ?, ppts_id = ?, vector_threshold = ?, comment = ?
            WHERE id = ?
            """,
            (
                rule.pattern,
                rule.match_type,
                rule.vendor_pattern,
                rule.vendor_match_type,
                rule.status,
                rule.ppts_id,
                rule.vector_threshold,
                rule.comment,
                rule.id,
            ),
        )
        self._conn.commit()
        updated = cursor.rowcount > 0
        if updated:
            logger.info("Updated rule id=%d", rule.id)
        return updated

    def delete_rule(self, rule_id: int) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM rules WHERE id = ?", (rule_id,))
        self._conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted rule id=%d", rule_id)
        return deleted

    def increment_match_count(self, rule_id: int) -> None:
        self._conn.execute(
            """
            UPDATE rules
            SET match_count = match_count + 1,
                last_matched_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (rule_id,),
        )
        self._conn.commit()

    def get_active_rules(self) -> list[KnowledgeBaseRule]:
        cursor = self._conn.execute(
            """
            SELECT * FROM rules
            ORDER BY
                CASE match_type
                    WHEN 'exact' THEN 1
                    WHEN 'contains' THEN 2
                    WHEN 'regex' THEN 3
                    WHEN 'vector' THEN 4
                END,
                id
            """
        )
        return [_row_to_rule(row) for row in cursor.fetchall()]

    def get_all_scripts(self) -> list[ScriptConfig]:
        cursor = self._conn.execute(
            "SELECT * FROM scripts_config ORDER BY priority, id")
        return [_row_to_script_config(row) for row in cursor.fetchall()]

    def get_enabled_scripts(self) -> list[ScriptConfig]:
        cursor = self._conn.execute(
            "SELECT * FROM scripts_config WHERE enabled = 1 ORDER BY priority, id"
        )
        return [_row_to_script_config(row) for row in cursor.fetchall()]

    def create_script_config(self, config: ScriptConfig) -> int:
        cursor = self._conn.execute(
            """
            INSERT INTO scripts_config (script_path, condition, priority, enabled)
            VALUES (?, ?, ?, ?)
            """,
            (config.script_path, config.condition,
             config.priority, int(config.enabled)),
        )
        self._conn.commit()
        return cursor.lastrowid

    def update_script_config(self, config: ScriptConfig) -> bool:
        cursor = self._conn.execute(
            """
            UPDATE scripts_config
            SET script_path = ?, condition = ?, priority = ?, enabled = ?
            WHERE id = ?
            """,
            (
                config.script_path,
                config.condition,
                config.priority,
                int(config.enabled),
                config.id,
            ),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_script_config(self, config_id: int) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM scripts_config WHERE id = ?", (config_id,))
        self._conn.commit()
        return cursor.rowcount > 0
