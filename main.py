import configparser
import logging
import os
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

import cloudflare_api as cf
from logger import setup as setup_logging
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
    parser = configparser.ConfigParser(interpolation=None)
    try:
        if not parser.read(CONFIG_FILE):
            raise SystemExit("Config file not found: %s" % CONFIG_FILE)
    except configparser.Error as exc:
        raise SystemExit("Invalid config.ini: %s" % exc)

    def section(name: str) -> dict[str, str]:
        return dict(parser[name]) if name in parser else {}

    block_urls, tld_urls = section("BlockLists"), section("TLDList")

    if not block_urls and not tld_urls:
        raise SystemExit("config.ini has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        raise SystemExit("Only one URL is supported in [TLDList]")
    for url in [*block_urls.values(), *tld_urls.values()]:
        if not url.startswith("https://"):
            raise SystemExit("URL must use https://: %s" % url)

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
    stripped = (
        line.strip()
        for line in raw.decode("utf-8", errors="ignore").lower().splitlines()
    )
    return [line for line in stripped if line and line[0] not in COMMENT_CHARS]


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
    """Return True if any proper dot-suffix of domain is in tld_set."""
    while "." in domain:
        domain = domain.partition(".")[2]
        if domain in tld_set:
            return True
    return False


def parse_domains(raw: bytes) -> set[str]:
    """Parse domains from raw bytes."""
    lines = _clean_lines(raw)
    if not lines:
        return set()

    tokens = [line.split(None, 1)[0] for line in lines[:30]]
    is_hosts = sum(token in HOSTS_IPS_SET for token in tokens) * 2 > len(tokens)

    if is_hosts:
        parts = (line.split(None, 2) for line in lines)
        return {
            p[1].rstrip(".")
            for p in parts
            if len(p) >= 2 and "localhost" not in p[1]
        }
    return {line.split(None, 1)[0].rstrip(".") for line in lines}


def _fetch(url: str, parse) -> set[str] | None:
    """Download + parse in the worker thread"""
    raw = download(url)
    return None if raw is None else parse(raw)


def main() -> None:
    load_dotenv()
    setup_logging()

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
    unique_block_urls = list(dict.fromkeys(block_urls.values()))

    # block-list fetches + TLD fetch + the two Cloudflare calls
    workers = min(len(unique_block_urls) + 3, MAX_DOWNLOAD_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rules_future = pool.submit(cf.get_rules, session, base)
        lists_future = pool.submit(cf.get_lists, session, base)

        domain_futures = {
            url: pool.submit(_fetch, url, parse_domains)
            for url in unique_block_urls
        }
        tld_future = pool.submit(_fetch, tld_url, parse_tlds) if tld_url else None

        results = {url: fut.result() for url, fut in domain_futures.items()}
        tld_result = tld_future.result() if tld_future else None

        block_failed = [url for url, res in results.items() if res is None]
        if block_failed:
            log.warning(
                "Skipping %s failed download(s): %s",
                v(len(block_failed)),
                v(", ".join(block_failed)),
            )

        tld_set: set[str] = tld_result or set()
        if tld_url and tld_result is None:
            log.warning("TLD list unavailable — no TLD-level blocking this run")

        all_domains: set[str] = set().union(
            *(res for res in results.values() if res is not None)
        )
        if tld_set:
            all_domains = {
                d for d in all_domains if not _tld_blocked(d, tld_set)
            }

        if block_failed and not all_domains:
            raise SystemExit(
                "All block-list downloads failed — not modifying Cloudflare"
            )

        all_rules = rules_future.result()
        all_lists = lists_future.result()

    cf.delete_rules_by_prefix(session, base, NAME_PREFIX_TLD, all_rules)
    if tld_set:
        cf.create_tld_rule(session, base, NAME_PREFIX_TLD, sorted(tld_set))

    if not all_domains:
        log.warning("No domains to block — removing existing lists/rule")
        cf.delete_rules_by_prefix(session, base, NAME_PREFIX, all_rules)
        cf.delete_lists_by_prefix(session, base, NAME_PREFIX, lists=all_lists)
        return

    sorted_domains = sorted(all_domains)
    chunks = [
        sorted_domains[i : i + CHUNK_SIZE]
        for i in range(0, len(sorted_domains), CHUNK_SIZE)
    ]

    extra_lists = sum(not item["name"].startswith(NAME_PREFIX) for item in all_lists)
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
    except cf.CloudflareAPIError as exc:
        log.critical("Cloudflare API error: %s", exc)
        raise SystemExit(64)
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        raise SystemExit(1)
