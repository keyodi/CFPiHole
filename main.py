from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import partial
from io import BytesIO
import configparser
import logging
import os
import time
from collections.abc import Iterator

import requests
from requests.adapters import HTTPAdapter

import cloudflare_api
from logger_config import CustomFormatter


# Constants
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE = "config.ini"
TIMEOUT = 15

# Cloudflare Gateway API limits
MAX_LISTS = 300
CHUNK_SIZE = 1000

# Concurrency limits based on system capabilities and API rate limits
MAX_DOWNLOAD_WORKERS = 32
MAX_PARSE_WORKERS = 16

COMMENT_CHARS = frozenset("!#;/[")

logger = CustomFormatter.configure_logger("main")

# Global cache for downloaded file contents (name -> bytes)
file_cache: dict[str, bytes] = {}


def download_file(session: requests.Session, url: str, name: str) -> None:
    """Download a file and store in memory cache."""
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        file_cache[name] = response.content
        size_kb = len(response.content) / 1024
        logger.info(f"Downloaded {url} ({size_kb:.0f} KB)")
    except requests.exceptions.Timeout:
        logger.error("Timeout downloading %s after %ds", url, TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        logger.error("Connection error downloading %s: %s", url, exc)
    except requests.exceptions.HTTPError as exc:
        logger.error("HTTP error downloading %s: %s", url, exc)
    except requests.RequestException as exc:
        logger.error("Error downloading %s: %s", url, exc)


def read_lines(name: str) -> list[str]:
    """Return non-empty, non-comment lines from cached file."""
    if name not in file_cache:
        logger.warning("Missing %s, skipping", name)
        return []

    raw = file_cache[name].decode("utf-8", errors="ignore")
    return [
        s
        for line in raw.splitlines()
        if (s := line.strip()) and s[0] not in COMMENT_CHARS
    ]


def parse_tld_file(name: str) -> set[str]:
    """Strip adblock syntax (||tld^) and return bare TLD strings."""
    tlds = {
        line.removeprefix("||")
        .removesuffix("^")
        for line in read_lines(name)
    }
    logger.info("TLDs loaded: %s%s", CustomFormatter.GREEN, len(tlds))
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


def parse_domain_file(name: str, content: bytes | None, tld_set: set[str]) -> set[str]:
    """Parse a downloaded blocklist and return a set of domains to block."""
    if not content:
        logger.warning("Missing %s, skipping", name)
        return set()

    raw = content.decode("utf-8", errors="ignore")
    lines = [
        s
        for line in raw.splitlines()
        if (s := line.strip()) and s[0] not in COMMENT_CHARS
    ]
    if not lines:
        return set()

    is_hosts = lines[0].startswith(("127.0.0.1 ", "0.0.0.0 "))

    def _extract(line: str) -> str | None:
        first, _, rest = line.partition(" ")
        domain = (rest.strip() if is_hosts and rest else first).lower().rstrip(".")
        if is_hosts and "localhost" in domain:
            return None
        if tld_set and is_tld_blocked(domain, tld_set):
            return None
        return domain

    domains = {d for line in lines if (d := _extract(line)) is not None}

    logger.debug("%s — domains: %s%s", name, CustomFormatter.YELLOW, len(domains))
    return domains


def validate_config(config: configparser.ConfigParser) -> bool:
    """Validate required configuration and list URLs."""
    if not config.has_section("Lists"):
        logger.error(
            "%s is missing [Lists], doesn't exist, or has duplicate values.",
            CONFIG_FILE,
        )
        return False

    for key, url in config.items("Lists"):
        if not url.startswith(("http://", "https://")):
            logger.error("Invalid URL for '%s': %s", key, url)
            return False

    return True


def chunk_list(items: list[str], chunk_size: int) -> Iterator[list[str]]:
    """Yield successive chunks of size chunk_size from items."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def run() -> None:
    """Main entry point: download, parse, and sync lists with Cloudflare."""
    start_time = time.time()
    
    if not os.path.exists(CONFIG_FILE):
        logger.error("Config file not found: %s", CONFIG_FILE)
        raise SystemExit(1)
    
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read(CONFIG_FILE)
    except configparser.Error as exc:
        logger.error("Failed to parse %s: %s", CONFIG_FILE, exc)
        raise SystemExit(1)

    if not validate_config(config):
        raise SystemExit(1)

    list_names = config.options("Lists")
    tld_files, block_files = [], []
    for n in list_names:
        (tld_files if "tld" in n.lower() else block_files).append(n)

    cf_lists, total_cf_lists = cloudflare_api.get_lists(NAME_PREFIX)
    extra_lists = len(total_cf_lists) - len(cf_lists)
    logger.debug("CFPiHole lists in Cloudflare: %s%s", CustomFormatter.YELLOW, len(cf_lists))
    logger.debug("Additional lists in Cloudflare: %s%s", CustomFormatter.YELLOW, extra_lists)

    logger.info("Starting concurrent downloads...")

    num_download_workers = max(1, min(len(list_names), MAX_DOWNLOAD_WORKERS))
    num_parse_workers = max(1, min(len(block_files), MAX_PARSE_WORKERS))

    # Reuse session across all download operations
    session = requests.Session()
    session.mount(
        "https://",
        HTTPAdapter(
            pool_maxsize=num_download_workers,
            pool_connections=num_download_workers
        )
    )
    
    download_start = time.time()
    with ThreadPoolExecutor(max_workers=num_download_workers) as ex:
        futures = [
            ex.submit(download_file, session, config["Lists"][n], n)
            for n in list_names
        ]
        for future in futures:
            future.result()
    
    download_elapsed = time.time() - download_start
    logger.info("Downloads completed in %.2fs", download_elapsed)

    # Parse TLDs if available
    tld_set: set[str] = parse_tld_file(tld_files[0]) if tld_files else set()

    parse_start = time.time()
    all_domains: set[str] = set()
    with ProcessPoolExecutor(max_workers=num_parse_workers) as ex:
        futures = [
            ex.submit(parse_domain_file, n, file_cache.get(n), tld_set)
            for n in block_files
        ]
        for future in futures:
            all_domains.update(future.result())
    
    parse_elapsed = time.time() - parse_start
    logger.info("Parsing completed in %.2fs", parse_elapsed)

    unique_count = len(all_domains)
    new_list_count = (unique_count - 1) // CHUNK_SIZE + 1

    logger.info("Unique domains: %s%s", CustomFormatter.GREEN, unique_count)
    logger.info("Lists to create: %s%s", CustomFormatter.GREEN, new_list_count)

    if unique_count == sum(l["count"] for l in cf_lists):
        logger.warning("Lists are the same size, stopping")
        return

    if (new_list_count + extra_lists) > MAX_LISTS:
        logger.warning(
            "Max %s lists allowed. Select smaller blocklists, stopping",
            MAX_LISTS,
        )
        return

    cloudflare_api.delete_policy(NAME_PREFIX_TLD)
    if tld_set:
        cloudflare_api.create_policy_with_tlds(NAME_PREFIX_TLD, sorted(tld_set))

    cloudflare_api.delete_lists_and_policy(NAME_PREFIX, cf_lists)
    cloudflare_api.create_lists_and_policy(NAME_PREFIX, sorted(all_domains))

    total_elapsed = time.time() - start_time
    logger.info("%sSync completed in %.2fs", CustomFormatter.GREEN, total_elapsed)


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        exit(130)
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        exit(1)
