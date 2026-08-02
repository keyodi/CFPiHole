"""Main entry point for CFPiHole.

This script downloads blocklists, parses domains and TLDs, and updates
Cloudflare lists and policies accordingly.
"""

from __future__ import annotations

import configparser
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import requests

import cloudflare_api
from logger_config import CustomFormatter

# Constants
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE = "config.ini"
TMP_DIR = Path("./tmp")
TIMEOUT = 15
MAX_LISTS = 300
CHUNK_SIZE = 1000
COMMENT_CHARS = frozenset("!#;/[")

logger = CustomFormatter.configure_logger("main")


def download_file(session: requests.Session, url: str, name: str) -> None:
    """Download a URL into the temporary directory using the provided session.

    Errors are logged but do not raise to the caller.
    """
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        (TMP_DIR / name).write_bytes(response.content)
        logger.info(f"Downloaded {url} ({len(response.content) / 1024:.0f} KB)")
    except requests.RequestException as exc:
        logger.error(f"Error downloading {url}: {exc}")


def read_lines(path: Path) -> list[str]:
    """Return non-empty, non-comment lines from a file.

    Lines are stripped of surrounding whitespace and comment lines (starting
    with any character in COMMENT_CHARS) are ignored.
    """
    if not path.exists():
        logger.warning(f"Missing {path}, skipping")
        return []

    raw = path.read_text(encoding="utf-8", errors="ignore")
    return [
        s
        for line in raw.splitlines()
        if (s := line.strip()) and s[0] not in COMMENT_CHARS
    ]


def parse_tld_file(name: str) -> set[str]:
    """Strip adblock syntax (e.g. "||tld^") and return bare TLD strings."""
    tlds = {
        line.removeprefix("||").removesuffix("^")
        for line in read_lines(TMP_DIR / name)
    }
    logger.info(f"TLDs loaded: {CustomFormatter.GREEN}{len(tlds)}")
    return tlds


def is_tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Return True if the domain ends with a TLD in tld_set.

    The function checks both single-label TLDs (e.g. 'com') and two-label
    public suffixes (e.g. 'co.uk').
    """
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2:
        if parts[-1] in tld_set:
            return True
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in tld_set:
            return True
    return False


def parse_domain_file(name: str, tld_set: set[str]) -> set[str]:
    """Parse a blocklist file and return a set of domains.

    Supports hosts-style files (starting with '127.0.0.1 ' or '0.0.0.0 ')
    and simple domain-per-line lists. Filters out localhost and TLDs if
    a tld_set is provided.
    """
    lines = read_lines(TMP_DIR / name)
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

    logger.debug(f"{name} — domains: {CustomFormatter.YELLOW}{len(domains)}")
    return domains


def validate_config(config: configparser.ConfigParser) -> bool:
    """Validate the parsed config file for required sections and URLs."""
    if not config.has_section("Lists"):
        logger.error(
            f"{CONFIG_FILE} is missing [Lists], doesn't exist, or has duplicate values."
        )
        return False

    for key, url in config.items("Lists"):
        if not url.startswith(("http://", "https://")):
            logger.error(f"Invalid URL for '{key}': {url}")
            return False

    return True


def run() -> None:
    """Main runner: download, parse, and update Cloudflare lists and policy."""
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not validate_config(config):
        return

    list_names = config.options("Lists")
    tld_files = [n for n in list_names if "tld" in n.lower()]
    block_files = [n for n in list_names if "tld" not in n.lower()]

    # Build Cloudflare API client from environment
    try:
        cf = cloudflare_api.from_env()
    except Exception as exc:  # pragma: no cover - environment errors
        logger.error("Could not initialize Cloudflare client: %s", exc)
        return

    try:
        cf_lists, total_cf_lists = cf.get_lists(NAME_PREFIX)
    except Exception as exc:
        logger.error("Error fetching lists from Cloudflare: %s", exc)
        return

    extra_lists = len(total_cf_lists) - len(cf_lists)
    logger.debug(f"CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}")
    logger.debug(f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{extra_lists}")

    logger.info("Starting concurrent downloads...")

    max_download_workers = min(len(list_names), 32)
    max_parse_workers = min(len(block_files), 16)

    with requests.Session() as session:
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
        for domain_set in ex.map(partial(parse_domain_file, tld_set=tld_set), block_files):
            all_domains.update(domain_set)

    unique_count = len(all_domains)
    new_list_count = (unique_count + CHUNK_SIZE - 1) // CHUNK_SIZE

    logger.info(f"Unique domains: {CustomFormatter.GREEN}{unique_count}")
    logger.info(f"Lists to create: {CustomFormatter.GREEN}{new_list_count}")

    if unique_count == sum(l["count"] for l in cf_lists):
        logger.warning("Lists are the same size, stopping")
        return

    if (new_list_count + extra_lists) > MAX_LISTS:
        logger.warning(
            f"Max {MAX_LISTS} lists allowed. Select smaller blocklists, stopping"
        )
        return

    # Update Cloudflare with TLDs and lists
    try:
        cf.delete_policy(NAME_PREFIX_TLD)
        if tld_set:
            cf.create_policy_with_tlds(NAME_PREFIX_TLD, sorted(tld_set))

        cf.delete_lists_and_policy(NAME_PREFIX, cf_lists)
        cf.create_lists_and_policy(NAME_PREFIX, sorted(all_domains))
    except Exception as exc:
        logger.error("Error updating Cloudflare: %s", exc)
        return

    logger.info(f"{CustomFormatter.GREEN}Done")


if __name__ == "__main__":
    run()
