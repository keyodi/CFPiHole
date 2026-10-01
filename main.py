import configparser
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
from typing import Iterator

import requests
from dotenv import load_dotenv

import cloudflare_api as cf
import logger
from cloudflare_api import CloudflareAPIError
from logger import v

NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE = "config.ini"

# Cloudflare Gateway API limits
MAX_LISTS = 300
CHUNK_SIZE = 1000

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

COMMENT_CHARS = frozenset("!#;/[")
HOSTS_IPS_SET = frozenset(("127.0.0.1", "0.0.0.0"))

log = logging.getLogger("cfpihole")


def load_config() -> tuple[dict[str, str], str | None]:
    """Read config.ini and return (block_urls, tld_url)."""
    if not os.path.exists(CONFIG_FILE):
        raise SystemExit("Config file not found: %s" % CONFIG_FILE)

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(CONFIG_FILE)
    except configparser.Error as exc:
        raise SystemExit("Invalid config.ini: %s" % exc)

    block_urls = (
        dict(parser.items("BlockLists"))
        if parser.has_section("BlockLists")
        else {}
    )
    tld_urls = (
        dict(parser.items("TLDList")) if parser.has_section("TLDList") else {}
    )

    if not block_urls and not tld_urls:
        raise SystemExit("config.ini has no [BlockLists] or [TLDList] entries")

    for url in [*block_urls.values(), *tld_urls.values()]:
        if not url.startswith("https://"):
            raise SystemExit("URL must use https://: %s" % url)

    if len(tld_urls) > 1:
        raise SystemExit("Only one URL is supported in [TLDList]")

    return block_urls, next(iter(tld_urls.values()), None)


def download(url: str) -> bytes | None:
    """Download a URL and return raw bytes, or None on failure."""
    try:
        response = requests.get(
            url, timeout=15, allow_redirects=True, stream=True
        )
        response.raise_for_status()
        if not response.url.startswith("https://"):
            log.error("Refused non-HTTPS redirect for %s", v(url))
            return None

        content = response.raw.read(MAX_DOWNLOAD_BYTES + 1, decode_content=True)
        if len(content) > MAX_DOWNLOAD_BYTES:
            log.error(
                "Refused response over %s MB for %s",
                v(MAX_DOWNLOAD_BYTES // (1024 * 1024)),
                v(url),
            )
            return None

        log.info("Downloaded: %s %s", v(url), v(f"{len(content) / 1024:.0f} KB"))
        return content
    except requests.RequestException as exc:
        log.error("Failed downloading %s: %s", v(url), v(exc))
        return None


def download_all(urls: list[str]) -> dict[str, bytes | None]:
    """Download URLs concurrently and return {url: bytes or None}."""
    unique_urls = list(dict.fromkeys(urls))
    if not unique_urls:
        return {}

    workers = min(len(unique_urls), 16)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(
            zip(unique_urls, pool.map(download, unique_urls), strict=True)
        )


def _clean_lines(raw: bytes) -> list[str]:
    """Return non-empty, non-comment lines from raw bytes."""
    lines: list[str] = []
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and stripped[0] not in COMMENT_CHARS:
            lines.append(stripped)
    return lines


def parse_tlds(raw: bytes) -> set[str]:
    """Extract TLDs from raw bytes and return a normalized set."""
    tlds: set[str] = set()
    for line in _clean_lines(raw):
        cleaned = "".join(
            char for char in line if char.isalnum() or char in "-."
        ).strip(".").lower()
        if cleaned:
            tlds.add(cleaned)
    return tlds


def _tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Return True if any proper dot-suffix of domain is in tld_set."""
    labels = domain.split(".")
    return any(
        ".".join(labels[index:]) in tld_set
        for index in range(1, len(labels))
    )


def parse_domains(raw: bytes, tld_set: set[str]) -> set[str]:
    """Parse domains from raw bytes, filtering by TLD set."""
    lines = _clean_lines(raw)
    if not lines:
        return set()

    sample_first_tokens = [line.split(maxsplit=1)[0] for line in lines[:30]]
    is_hosts = (
        sum(token in HOSTS_IPS_SET for token in sample_first_tokens)
        > len(sample_first_tokens) / 2
    )

    domains: set[str] = set()
    for line in lines:
        parts = line.split()
        if is_hosts:
            if len(parts) < 2:
                continue
            domain = parts[1].lower().rstrip(".")
            if "localhost" in domain:
                continue
        else:
            domain = parts[0].lower().rstrip(".")

        if not tld_set or not _tld_blocked(domain, tld_set):
            domains.add(domain)

    return domains


def chunk_generator(items: list[str], chunk_size: int) -> Iterator[list[str]]:
    """Yield chunks of items lazily without materializing all at once."""
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, chunk_size))
        if not chunk:
            break
        yield chunk


def main() -> None:
    load_dotenv()
    logger.setup()

    cf_api_token = os.getenv("CF_API_TOKEN")
    if not cf_api_token:
        raise SystemExit("Missing CF_API_TOKEN")

    cf_identifier = os.getenv("CF_IDENTIFIER")
    if not cf_identifier:
        raise SystemExit("Missing CF_IDENTIFIER")

    base = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{cf_identifier}/gateway"
    )

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {cf_api_token}"

    block_urls, tld_url = load_config()
    urls = list(block_urls.values())
    if tld_url:
        urls.append(tld_url)
    downloads = download_all(urls)

    failed_urls = [url for url in urls if downloads.get(url) is None]
    if failed_urls:
        log.warning(
            "Skipping %s failed download(s): %s",
            v(len(failed_urls)),
            v(", ".join(failed_urls)),
        )

    tld_set: set[str] = set()
    if tld_url:
        raw = downloads[tld_url]
        if raw:
            tld_set = parse_tlds(raw)
        else:
            log.warning("TLD list unavailable — no TLD-level blocking this run")

    all_domains: set[str] = set()
    any_failed = False
    for url in block_urls.values():
        raw = downloads[url]
        if raw is None:
            any_failed = True
        else:
            all_domains.update(parse_domains(raw, tld_set))

    if block_urls and any_failed and not all_domains:
        raise SystemExit(
            "All block-list downloads failed — not modifying Cloudflare"
        )

    all_rules = cf.get_rules(session, base)
    cf.delete_rules_by_prefix(session, base, NAME_PREFIX_TLD, all_rules)
    if tld_set:
        cf.create_tld_rule(session, base, NAME_PREFIX_TLD, sorted(tld_set))

    all_lists = cf.get_lists(session, base)
    existing_lists = [
        item for item in all_lists if item["name"].startswith(NAME_PREFIX)
    ]

    if not all_domains:
        log.warning("No domains to block — removing existing lists/rule")
        cf.delete_rules_by_prefix(session, base, NAME_PREFIX, all_rules)
        cf.delete_lists_by_prefix(session, base, NAME_PREFIX, lists=all_lists)
        return

    sorted_domains = sorted(all_domains)
    chunks = list(chunk_generator(sorted_domains, CHUNK_SIZE))

    extra_lists = len(all_lists) - len(existing_lists)
    if len(chunks) + extra_lists > MAX_LISTS:
        raise SystemExit(
            "Would exceed %s list limit — use smaller block lists" % MAX_LISTS
        )

    log.info(
        "Unique domains: %s → %s lists",
        v(len(sorted_domains)),
        v(len(chunks)),
    )

    cf.delete_rules_by_prefix(session, base, NAME_PREFIX, all_rules)
    log.info("Deleting lists, please wait")
    cf.delete_lists_by_prefix(session, base, NAME_PREFIX, lists=all_lists)

    log.info("Creating lists, please wait")
    list_ids = [
        cf.create_list(session, base, f"{NAME_PREFIX} {index}", chunk)
        for index, chunk in enumerate(chunks, 1)
    ]
    cf.create_domain_rule(session, base, NAME_PREFIX, list_ids)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except SystemExit:
        raise
    except CloudflareAPIError as exc:
        log.critical("Cloudflare API error: %s", exc)
        raise SystemExit(64)
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        raise SystemExit(1)
