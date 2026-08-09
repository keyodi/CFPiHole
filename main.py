from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from io import BytesIO
import configparser
import logging
import requests

import cloudflare_api
from logger_config import CustomFormatter


# Constants
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE = "config.ini"
TIMEOUT = 15
MAX_LISTS = 300
CHUNK_SIZE = 1000
COMMENT_CHARS = frozenset("!#;/[")

logger = CustomFormatter.configure_logger("main")

# Global cache for downloaded file contents (name -> bytes)
file_cache: dict[str, bytes] = {}


def download_file(session: requests.Session, url: str, name: str) -> None:
    """Download a file and store in memory."""
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        file_cache[name] = response.content
        size_kb = len(response.content) / 1024
        logger.info(f"Downloaded {url} ({size_kb:.0f} KB)")
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
        line.removeprefix("||").removesuffix("^")
        for line in read_lines(name)
    }
    logger.info("TLDs loaded: %s%s", CustomFormatter.GREEN, len(tlds))
    return tlds

def is_tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Return True if the domain's TLD (or second-level TLD) is in tld_set."""
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2:
        if parts[-1] in tld_set:
            return True
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in tld_set:
            return True
    return False

def parse_domain_file(name: str, tld_set: set[str]) -> set[str]:
    """Parse a downloaded blocklist and return a set of domains to block."""
    lines = read_lines(name)
    if not lines:
        return set()

    is_hosts = lines[0].startswith(("127.0.0.1 ", "0.0.0.0 "))
    domains: set[str] = set()

    for line in lines:
        # partition avoids allocating a full split list for every line
        first, _, rest = line.partition(" ")
        domain = (rest.strip() if is_hosts and rest else first).lower().rstrip(".")
        if is_hosts and "localhost" in domain:
            continue
        if tld_set and is_tld_blocked(domain, tld_set):
            continue
        domains.add(domain)

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

def run() -> None:
    """Main entry point: download, parse, and sync lists with Cloudflare."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not validate_config(config):
        return

    list_names = config.options("Lists")
    tld_files, block_files = [], []
    for n in list_names:
        (tld_files if "tld" in n.lower() else block_files).append(n)

    cf_lists, total_cf_lists = cloudflare_api.get_lists(NAME_PREFIX)
    extra_lists = len(total_cf_lists) - len(cf_lists)
    logger.debug("CFPiHole lists in Cloudflare: %s%s", CustomFormatter.YELLOW, len(cf_lists))
    logger.debug("Additional lists in Cloudflare: %s%s", CustomFormatter.YELLOW, extra_lists)

    logger.info("Starting concurrent downloads...")

    max_download_workers = max(1, min(len(list_names), 32))
    max_parse_workers = max(1, min(len(block_files), 16))

    # Reuse session across all download operations
    session = requests.Session()
    with ThreadPoolExecutor(max_workers=max_download_workers) as ex:
        futures = [
            ex.submit(download_file, session, config["Lists"][n], n)
            for n in list_names
        ]
        for future in futures:
            future.result()

    # Parse TLDs if available
    tld_set: set[str] = parse_tld_file(tld_files[0]) if tld_files else set()

    # Parse all block files concurrently and stream results
    all_domains: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_parse_workers) as ex:
        for domain_set in ex.map(
            partial(parse_domain_file, tld_set=tld_set), block_files
        ):
            all_domains.update(domain_set)

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

    logger.info("%sDone", CustomFormatter.GREEN)


if __name__ == "__main__":
    run()
