from __future__ import annotations

import configparser
import os

import requests

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

COMMENT_CHARS = frozenset("!#;/[")

logger = CustomFormatter.configure_logger("main")


def download_file(
    session: requests.Session, url: str, name: str
) -> tuple[str, bytes] | None:
    """Download a file and return (name, content), or None on failure."""
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        logger.info("Downloaded %s (%.0f KB)", url, len(response.content) / 1024)
        return name, response.content
    except requests.RequestException as exc:
        logger.error("Failed downloading %s: %s", url, exc)
        return None


def read_lines(name: str, file_cache: dict[str, bytes]) -> list[str]:
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


def parse_tld_file(name: str, file_cache: dict[str, bytes]) -> set[str]:
    """Skip comment lines, strip characters other than alphanumerics, hyphens, and dots."""
    tlds = {
        cleaned
        for line in read_lines(name, file_cache)
        if (cleaned := "".join(ch for ch in line if ch.isalnum() or ch in "-.").strip("."))
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


def parse_domain_file(
    source_name: str, tld_set: set[str], file_cache: dict[str, bytes]
) -> set[str]:
    """Parse a cached blocklist and return a set of domains to block."""
    lines = read_lines(source_name, file_cache)
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

    logger.debug("%s — domains: %s%s", source_name, CustomFormatter.YELLOW, len(domains))
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

    logger.info("Starting downloads (sequential)...")

    session = requests.Session()

    # Sequential download loop
    file_cache: dict[str, bytes] = {}
    for n in list_names:
        result = download_file(session, config["Lists"][n], n)
        if result is not None:
            name, content = result
            file_cache[name] = content

    # Parse TLDs if available and silently ignoring extras beyond index 0
    tld_set: set[str] = parse_tld_file(tld_files[0], file_cache) if tld_files else set()

    all_domains: set[str] = set()
    for n in block_files:
        all_domains.update(parse_domain_file(n, tld_set, file_cache))

    unique_count = len(all_domains)
    new_list_count = (unique_count - 1) // CHUNK_SIZE + 1

    logger.info("Unique domains: %s%s", CustomFormatter.GREEN, unique_count)
    logger.info("Lists to create: %s%s", CustomFormatter.GREEN, new_list_count)

    cf_total = sum(lst.get("count", 0) for lst in cf_lists)
    if unique_count == cf_total:
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
    cloudflare_api.create_lists_and_policy(NAME_PREFIX, sorted(all_domains), chunk_size=CHUNK_SIZE)


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
