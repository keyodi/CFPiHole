from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter

from logger_config import CustomFormatter

logger = CustomFormatter.configure_logger("sources")

COMMENT_CHARS = frozenset("!#;/[")
DOWNLOAD_TIMEOUT = 15
MAX_DOWNLOAD_WORKERS = 32


@dataclass(frozen=True)
class FetchResult:
    """Result of fetching a set of named URLs."""

    content: dict[str, bytes] = field(default_factory=dict)
    failed: list[str] = field(default_factory=list)


def fetch_all(urls: dict[str, str]) -> FetchResult:
    """Download all URLs concurrently. Per-URL failures are recorded, not raised."""
    workers = max(1, min(len(urls), MAX_DOWNLOAD_WORKERS))
    session = requests.Session()
    session.mount("https://", HTTPAdapter(pool_maxsize=workers, pool_connections=workers))

    def _fetch(name: str, url: str) -> tuple[str, bytes | None]:
        try:
            response = session.get(url, allow_redirects=True, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            logger.info("Downloaded %s (%.0f KB)", url, len(response.content) / 1024)
            return name, response.content
        except requests.RequestException as exc:
            logger.error("Failed downloading %s: %s", url, exc)
            return name, None

    content: dict[str, bytes] = {}
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for name, data in ex.map(lambda item: _fetch(*item), urls.items()):
            if data is None:
                failed.append(name)
            else:
                content[name] = data

    return FetchResult(content=content, failed=failed)


def _lines(raw: bytes) -> list[str]:
    """Return non-empty, non-comment lines from raw file bytes."""
    text = raw.decode("utf-8", errors="ignore")
    return [s for line in text.splitlines() if (s := line.strip()) and s[0] not in COMMENT_CHARS]


def parse_tlds(raw: bytes) -> set[str]:
    """Skip comment lines, strip characters other than alphanumerics, hyphens, and dots."""
    tlds = set()
    for line in _lines(raw):
        allowed_chars = "".join(ch for ch in line if ch.isalnum() or ch in "-.")
        cleaned = allowed_chars.strip(".")
        if cleaned:
            tlds.add(cleaned)
    logger.debug("Parsed %s TLDs", len(tlds))
    return tlds


def is_tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Check if domain's TLD or second-level TLD is in the blocklist."""
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2:
        if parts[-1] in tld_set:
            return True
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in tld_set:
            return True
    return False


def parse_domains(raw: bytes, tld_set: set[str]) -> set[str]:
    """Parse a blocklist (plain-domain or hosts format) into a set of domains."""
    lines = _lines(raw)
    if not lines:
        return set()

    is_hosts = lines[0].startswith(("127.0.0.1 ", "0.0.0.0 "))

    def _extract(line: str) -> str | None:
        # Hosts-format lines may list multiple hostnames after the IP
        # (e.g. "0.0.0.0 example.com www.example.com"); take the first.
        parts = line.split()
        domain = (parts[1] if is_hosts and len(parts) > 1 else parts[0]).lower().rstrip(".")
        if is_hosts and "localhost" in domain:
            return None
        if tld_set and is_tld_blocked(domain, tld_set):
            return None
        return domain

    return {d for line in lines if (d := _extract(line)) is not None}
