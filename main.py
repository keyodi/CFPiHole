import configparser
import logging
import os
from concurrent.futures import ThreadPoolExecutor

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

MAX_DOWNLOAD_WORKERS = 16

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
        with requests.get(
            url, timeout=15, allow_redirects=True, stream=True
        ) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", v(url))
                return None

            buf = bytearray()
            for part in response.iter_content(chunk_size=65536):
                buf += part
                if len(buf) > MAX_DOWNLOAD_BYTES:
                    log.error(
                        "Refused response over %s MB for %s",
                        v(MAX_DOWNLOAD_BYTES // (1024 * 1024)),
                        v(url),
                    )
                    return None

        content = bytes(buf)
        log.info("Downloaded: %s %s", v(url), v(f"{len(content) / 1024:.0f} KB"))
        return content
    except requests.RequestException as exc:
        log.error("Failed downloading %s: %s", v(url), v(exc))
        return None


def _clean_lines(raw: bytes) -> list[str]:
    """Return non-empty, non-comment, lower-cased lines from raw bytes."""
    text = raw.decode("utf-8", errors="ignore").lower()
    comment_chars = COMMENT_CHARS
    lines: list[str] = []
    append = lines.append
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and stripped[0] not in comment_chars:
            append(stripped)
    return lines


def parse_tlds(raw: bytes) -> set[str]:
    """Extract TLDs from raw bytes and return a normalized set."""
    tlds: set[str] = set()
    for line in _clean_lines(raw):
        cleaned = "".join(
            char for char in line if char.isalnum() or char in "-."
        ).strip(".")
        if cleaned:
            tlds.add(cleaned)
    return tlds


def _tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Return True if any proper dot-suffix of domain is in tld_set.

    Walks dots with str.find and slices, avoiding the split()/join() of every
    suffix that the naive version performs per domain.
    """
    find = domain.find
    idx = find(".")
    while idx != -1:
        if domain[idx + 1:] in tld_set:
            return True
        idx = find(".", idx + 1)
    return False


def parse_domains(raw: bytes) -> set[str]:
    """Parse domains from raw bytes (TLD filtering is applied later, once,
    on the de-duplicated union of all lists)."""
    lines = _clean_lines(raw)
    if not lines:
        return set()

    sample_first_tokens = [line.split(None, 1)[0] for line in lines[:30]]
    is_hosts = (
        sum(token in HOSTS_IPS_SET for token in sample_first_tokens)
        > len(sample_first_tokens) / 2
    )

    domains: set[str] = set()
    add = domains.add
    if is_hosts:
        for line in lines:
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            domain = parts[1].rstrip(".")
            if "localhost" not in domain:
                add(domain)
    else:
        for line in lines:
            add(line.split(None, 1)[0].rstrip("."))
    return domains


def _fetch_domains(url: str) -> set[str] | None:
    """Download + parse in the worker thread so CPU parsing of one list
    overlaps with the network wait of the others."""
    raw = download(url)
    return None if raw is None else parse_domains(raw)


def _fetch_tlds(url: str) -> set[str] | None:
    raw = download(url)
    return parse_tlds(raw) if raw else None


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
    urls = list(dict.fromkeys([*block_urls.values(), *([tld_url] if tld_url else [])]))

    workers = min(len(urls) + 2, MAX_DOWNLOAD_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rules_future = pool.submit(cf.get_rules, session, base)
        lists_future = pool.submit(cf.get_lists, session, base)

        domain_futures = {
            url: pool.submit(_fetch_domains, url)
            for url in dict.fromkeys(block_urls.values())
        }
        tld_future = pool.submit(_fetch_tlds, tld_url) if tld_url else None

        results = {url: fut.result() for url, fut in domain_futures.items()}
        tld_result = tld_future.result() if tld_future else None

        failed_urls = [url for url, res in results.items() if res is None]
        if tld_url and tld_result is None:
            failed_urls.append(tld_url)
        if failed_urls:
            log.warning(
                "Skipping %s failed download(s): %s",
                v(len(failed_urls)),
                v(", ".join(failed_urls)),
            )

        tld_set: set[str] = tld_result or set()
        if tld_url and tld_result is None:
            log.warning("TLD list unavailable — no TLD-level blocking this run")

        all_domains: set[str] = set().union(
            *(res for res in results.values() if res is not None)
        )
        any_failed = any(res is None for res in results.values())
        if tld_set:
            all_domains = {
                d for d in all_domains if not _tld_blocked(d, tld_set)
            }

        if block_urls and any_failed and not all_domains:
            raise SystemExit(
                "All block-list downloads failed — not modifying Cloudflare"
            )

        all_rules = rules_future.result()
        all_lists = lists_future.result()

    cf.delete_rules_by_prefix(session, base, NAME_PREFIX_TLD, all_rules)
    if tld_set:
        cf.create_tld_rule(session, base, NAME_PREFIX_TLD, sorted(tld_set))

    existing_lists = [
        item for item in all_lists if item["name"].startswith(NAME_PREFIX)
    ]

    if not all_domains:
        log.warning("No domains to block — removing existing lists/rule")
        cf.delete_rules_by_prefix(session, base, NAME_PREFIX, all_rules)
        cf.delete_lists_by_prefix(session, base, NAME_PREFIX, lists=all_lists)
        return

    sorted_domains = sorted(all_domains)
    chunks = [
        sorted_domains[i:i + CHUNK_SIZE]
        for i in range(0, len(sorted_domains), CHUNK_SIZE)
    ]

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
