"""
Pydantic schema for BBOT's global config and preset files.

The top-level `BBOTConfig` mirrors the structure of `defaults.yml`. Per-module
configs are validated separately at bake time against each module's own
`class Config(BaseModuleConfig)` (see `BaseModuleConfig` below).
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


STRICT = ConfigDict(extra="forbid")


class ScopeConfig(BaseModel):
    model_config = STRICT

    strict: bool = False
    report_distance: int = 0
    search_distance: int = 0


class DnsConfig(BaseModel):
    model_config = STRICT

    disable: bool = False
    minimal: bool = False
    threads: int = 10
    cache_size: int = 100000
    brute_threads: int = 1000
    brute_nameservers: str = (
        "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
    )
    search_distance: int = 1
    runaway_limit: int = 5
    timeout: int = 5
    retries: int = 1
    wildcard_disable: bool = False
    wildcard_ignore: list[str] = Field(default_factory=list)
    wildcard_tests: int = 10
    abort_threshold: int = 10
    filter_ptrs: bool = True
    debug: bool = False
    omit_queries: list[str] = Field(
        default_factory=lambda: [
            "SRV:mail.protection.outlook.com",
            "CNAME:mail.protection.outlook.com",
            "TXT:mail.protection.outlook.com",
        ]
    )


class WebConfig(BaseModel):
    model_config = STRICT

    http_proxy: Optional[str] = None
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.97"
    )
    user_agent_suffix: Optional[str] = None
    spider_distance: int = 0
    spider_depth: int = 1
    spider_links_per_page: int = 25
    http_timeout: int = 10
    httpx_timeout: int = 5
    http_headers: dict[str, str] = Field(default_factory=dict)
    http_cookies: dict[str, str] = Field(default_factory=dict)
    api_retries: int = 2
    http_retries: int = 1
    httpx_retries: int = 1
    sleep_interval_429: int = Field(30, alias="429_sleep_interval")
    max_sleep_interval_429: int = Field(60, alias="429_max_sleep_interval")
    debug: bool = False
    http_max_redirects: int = 5
    ssl_verify: bool = False


class EngineConfig(BaseModel):
    model_config = STRICT

    debug: bool = False


class DepsToolConfig(BaseModel):
    """Per-tool dep config, e.g. deps.ffuf.version"""

    model_config = STRICT

    version: Optional[str] = None


class DepsConfig(BaseModel):
    model_config = STRICT

    behavior: str = "abort_on_failure"
    ffuf: DepsToolConfig = Field(default_factory=lambda: DepsToolConfig(version="2.1.0"))


class BaseModuleConfig(BaseModel):
    """
    Shared base for every module's `class Config(BaseModuleConfig)`.
    Carries the three universal module options that are applied to every
    module regardless of declaration.
    """

    model_config = STRICT

    batch_size: int = 10
    module_threads: int = 5
    module_timeout: int = 3600


class BBOTConfig(BaseSettings):
    """
    Root BBOT config. Mirrors `bbot/defaults.yml`.

    Unknown top-level keys raise ValidationError. This is what catches typos
    like `scpoe:` or `moudules:` in user configs.
    """

    model_config = SettingsConfigDict(
        extra="forbid",
        env_prefix="BBOT_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # Basic options
    home: str = "~/.bbot"
    keep_scans: int = 20
    status_frequency: int = 15
    file_blobs: bool = False
    folder_blobs: bool = False

    # Scope / DNS / Web / Engine / Deps
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    deps: DepsConfig = Field(default_factory=DepsConfig)

    # Module loader paths
    module_dirs: list[str] = Field(default_factory=list)

    # Module runtime
    module_handle_event_timeout: int = 3600
    module_handle_batch_timeout: int = 7200

    # Internal module toggles (these are hardcoded because they're first-class
    # features of the scan pipeline; the set changes rarely)
    speculate: bool = True
    excavate: bool = True
    aggregate: bool = True
    dnsresolve: bool = True
    cloudcheck: bool = True

    # URL handling
    url_querystring_remove: bool = True
    url_querystring_collapse: bool = True
    url_extension_blacklist: list[str] = Field(
        default_factory=lambda: [
            "png",
            "jpg",
            "bmp",
            "ico",
            "jpeg",
            "gif",
            "svg",
            "webp",
            "css",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "sass",
            "scss",
            "mp3",
            "m4a",
            "wav",
            "flac",
            "mp4",
            "mkv",
            "avi",
            "wmv",
            "mov",
            "flv",
            "webm",
        ]
    )
    url_extension_special: list[str] = Field(default_factory=lambda: ["js"])
    url_extension_static: list[str] = Field(
        default_factory=lambda: [
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "txt",
            "csv",
            "xml",
            "yaml",
            "ini",
            "log",
            "conf",
            "cfg",
            "env",
            "md",
            "rtf",
            "tiff",
            "bmp",
            "jpg",
            "jpeg",
            "png",
            "gif",
            "svg",
            "ico",
            "mp3",
            "wav",
            "flac",
            "mp4",
            "mov",
            "avi",
            "mkv",
            "webm",
            "zip",
            "tar",
            "gz",
            "bz2",
            "7z",
            "rar",
        ]
    )

    # Parameter handling
    parameter_blacklist: list[str] = Field(
        default_factory=lambda: [
            "__VIEWSTATE",
            "__EVENTARGUMENT",
            "__EVENTVALIDATION",
            "__EVENTTARGET",
            "__VIEWSTATEGENERATOR",
            "__SCROLLPOSITIONY",
            "__SCROLLPOSITIONX",
            "ASP.NET_SessionId",
            ".AspNetCore.Session",
            "PHPSESSID",
            "__cf_bm",
            "f5_cspm",
        ]
    )
    parameter_blacklist_prefixes: list[str] = Field(
        default_factory=lambda: [
            "TS01",
            "BIGipServer",
            "f5avr",
            "incap_",
            "visid_incap_",
            "AWSALB",
            "utm_",
            "ApplicationGatewayAffinity",
            "JSESSIONID",
            "ARRAffinity",
        ]
    )

    # Event output filter
    omit_event_types: list[str] = Field(
        default_factory=lambda: [
            "HTTP_RESPONSE",
            "RAW_TEXT",
            "URL_UNVERIFIED",
            "DNS_NAME_UNRESOLVED",
            "FILESYSTEM",
            "WEB_PARAMETER",
            "RAW_DNS_RECORD",
        ]
    )

    # Interactsh
    interactsh_server: Optional[str] = None
    interactsh_token: Optional[str] = None
    interactsh_disable: bool = False

    # Per-module configs — validated separately, per-module, at bake time.
    # Stored here as raw dicts so the root validator accepts any module
    # registered at preload time.
    modules: dict[str, dict[str, Any]] = Field(default_factory=dict)


class PresetSchema(BaseModel):
    """
    Schema for the top-level keys in a preset YAML file. Catches typos like
    `modlues:` or `flgas:` at load time.

    `target`/`targets` and `include`/`presets` are aliases; both accepted.
    `config` is validated separately as `BBOTConfig`.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    target: Optional[list[str]] = Field(default=None)
    targets: Optional[list[str]] = Field(default=None)
    seeds: Optional[list[str]] = None
    blacklist: Optional[list[str]] = None

    modules: Optional[list[str]] = None
    output_modules: Optional[list[str]] = None
    exclude_modules: Optional[list[str]] = None
    flags: Optional[list[str]] = None
    require_flags: Optional[list[str]] = None
    exclude_flags: Optional[list[str]] = None

    config: Optional[dict[str, Any]] = None
    module_dirs: Optional[list[str]] = None

    include: Optional[list[str]] = None
    presets: Optional[list[str]] = None

    scan_name: Optional[str] = None
    output_dir: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None

    conditions: Optional[list[str]] = None

    verbose: bool = False
    debug: bool = False
    silent: bool = False


__all__ = [
    "BBOTConfig",
    "BaseModuleConfig",
    "DepsConfig",
    "DepsToolConfig",
    "DnsConfig",
    "EngineConfig",
    "PresetSchema",
    "ScopeConfig",
    "WebConfig",
]
