"""Интерфейс хранилища правил базы знаний."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from status.core.models import KnowledgeBaseRule, ScriptConfig


class RuleRepositoryPort(ABC):

    @abstractmethod
    def get_all_rules(self) -> list[KnowledgeBaseRule]:
        ...

    @abstractmethod
    def get_rule_by_id(self, rule_id: int) -> KnowledgeBaseRule | None:
        ...

    @abstractmethod
    def search_rules(
        self,
        pattern: str | None = None,
        match_type: str | None = None,
        status: str | None = None,
    ) -> list[KnowledgeBaseRule]:
        ...

    @abstractmethod
    def create_rule(self, rule: KnowledgeBaseRule) -> int:
        ...

    @abstractmethod
    def update_rule(self, rule: KnowledgeBaseRule) -> bool:
        ...

    @abstractmethod
    def delete_rule(self, rule_id: int) -> bool:
        ...

    @abstractmethod
    def increment_match_count(self, rule_id: int) -> None:
        ...

    @abstractmethod
    def get_active_rules(self) -> list[KnowledgeBaseRule]:
        ...


class ScriptConfigPort(ABC):

    @abstractmethod
    def get_all_scripts(self) -> list[ScriptConfig]:
        ...

    @abstractmethod
    def get_enabled_scripts(self) -> list[ScriptConfig]:
        ...

    @abstractmethod
    def create_script_config(self, config: ScriptConfig) -> int:
        ...

    @abstractmethod
    def update_script_config(self, config: ScriptConfig) -> bool:
        ...

    @abstractmethod
    def delete_script_config(self, config_id: int) -> bool:
        ...
