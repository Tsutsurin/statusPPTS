"""Модели данных: уязвимость, позиция ППТС, кандидат, результаты анализа, настройки."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VulnerabilityPair:

    vendor: str
    product: str
    versions: list[str] = field(default_factory=list)
    raw_text: str = ""


@dataclass
class Vulnerability:

    cve_id: str
    vendor: str
    product: str
    version: str
    raw_text: str
    cvss: str = ""
    source_url: str = ""
    original_product: str = ""
    pairs: list[VulnerabilityPair] = field(default_factory=list)


@dataclass
class Software:

    id: str
    name: str
    vendor: str
    source: str
    original_name: str = ''
    original_vendor: str = ''


@dataclass
class JournalEntry:

    cve_id: str
    status: str
    ppts_id: str
    responsible: str
    product: str = ""
    source_file: str = ""


@dataclass
class MatchCandidate:

    software: Software
    vector_score: float = 0.0
    fuzzy_score: float = 0.0
    exact_score: float = 0.0
    combined_score: float = 0.0
    implied_status: str | None = None
    channel: str = ""
    channel_only: bool = False


@dataclass
class PairAnalysisResult:

    vendor: str
    product: str
    versions: list[str] = field(default_factory=list)
    status: str = ""
    status_source: str = ""
    candidates: list[MatchCandidate] = field(default_factory=list)
    ppts_id: str | None = None
    exclude_from_report: bool = False
    include_only: bool = False
    match_type: str = ""

    original_status: str = ""
    original_ppts_id: str | None = None
    original_status_source: str = ""


@dataclass
class AnalysisResult:

    vulnerability: Vulnerability
    status: str
    status_source: str
    candidates: list[MatchCandidate] = field(default_factory=list)
    ppts_id: str | None = None
    responsible: str | None = None
    journal_matches: list[JournalEntry] = field(default_factory=list)
    match_type: str | None = None
    pair_results: list[PairAnalysisResult] = field(default_factory=list)
    journal_no_candidates: bool = False
    manually_edited: bool = False


@dataclass
class KnowledgeBaseRule:

    id: int | None = None
    pattern: str = ""
    match_type: str = "exact"
    vendor_pattern: str = ""
    vendor_match_type: str = "contains"
    status: str = ""
    ppts_id: str | None = None
    vector_threshold: float | None = None
    comment: str | None = None
    created_at: str | None = None
    last_matched_at: str | None = None
    match_count: int = 0


@dataclass
class PptsColumnMapping:

    file_path: str = ""
    col_id: int | None = None
    col_name: int | None = None
    col_vendor: int | None = None
    headers: list[str] = field(default_factory=list)
    header_row: int = 0


@dataclass
class ScriptConfig:

    id: int | None = None
    script_path: str = ""
    condition: str = ""
    priority: int = 0
    enabled: bool = True


@dataclass
class PipelineSettings:

    top_n: int = 10
    vector_threshold: float = 0.35
    fuzzy_threshold: int = 75
    transliteration_direction: str = "to_en"
    min_word_length: int = 2
    use_knowledge_base: bool = False
    kb_path: str = ".data/knowledge.db"
    journal_paths: list[str] = field(default_factory=list)
    theme: str = "Светлая"
    detail_primary_limit: int = 0
    detail_secondary_limit: int = 3
    use_preprocessing: bool = True
    clean_noise_enabled: bool = True
    clean_noise_patterns: str = (
        "\\((?:R|TM|C|r|tm|c)\\)\n"
        "\\s+for\\s+(?:windows|x64|x86|arm|64-bit|32-bit)[\\w\\s-]*\n"
        "\\s+service\\s+pack\\s+\\d*\n"
        "\\s*(?:update\\s+)?KB\\d{6,}\n"
        "\\s+(?:Enterprise|Professional|Pro|Home|Standard|Datacenter|Ultimate|Premium|Starter)\\b"
    )
    clean_versions_enabled: bool = True
    clean_versions_patterns: str = (
        "\\b[vV]?\\d+(?:\\.\\d+){1,4}\\b\n"
        "\\b20[12]\\d\\b\n"
        "\\bversion\\b(?:\\s+\\S+)?"
    )
    split_multiproduct_enabled: bool = True
    split_delimiters: str = ";, /,  и , ,"
    scripts_dir: str = ".data/scripts"
    journal_recheck: bool = True
    weight_vector: float = 0.35
    weight_fuzzy: float = 0.40
    weight_exact: float = 0.25
    auto_match_threshold: float = 0.8
    candidate_mode: str = "all"
    candidate_relative: float = 0.75
    vector_vocab_mode: str = "frequency"
    vector_max_features: int = 2000
    parser_exe: str = ""
    parser_workers: int = 2
    parser_timeout_min: int = 60
    candidate_channels: bool = True
    duty_list_size: int = 5
    keep_channel_candidates: bool = True
    no_auto_yes_with_os: bool = True
    confident_no: str = "vendor<0.6"
    auto_match_margin: float = 0.0
    hide_weak_in_auto_no: bool = True