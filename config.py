from __future__ import annotations

import configparser
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    block_list_urls: dict[str, str]
    tld_list_url: str | None


def _validate_urls(section_name: str, urls: dict[str, str]) -> None:
    for key, url in urls.items():
        if not url.startswith("https://"):
            raise SystemExit(f"Invalid URL for [{section_name}] '{key}': must use https:// ({url})")


def load_config(path: str) -> Config:
    """Load and validate config.ini."""
    if not os.path.exists(path):
        raise SystemExit(f"Config file not found: {path}")

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path)
    except configparser.Error as exc:
        raise SystemExit(f"Failed to parse {path}: {exc}")

    block_urls = dict(parser.items("BlockLists")) if parser.has_section("BlockLists") else {}
    tld_urls = dict(parser.items("TLDList")) if parser.has_section("TLDList") else {}

    if not block_urls and not tld_urls:
        raise SystemExit(f"{path} has no [BlockLists] or [TLDList] entries")

    _validate_urls("BlockLists", block_urls)
    _validate_urls("TLDList", tld_urls)

    if len(tld_urls) > 1:
        raise SystemExit("Only one URL is supported in [TLDList]")

    return Config(block_list_urls=block_urls, tld_list_url=next(iter(tld_urls.values()), None))
