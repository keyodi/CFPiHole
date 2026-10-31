import configparser
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

import cloudflare_api as cloudflare
from logger import highlight, setup_logging

MAX_BYTES = 10 * 1024 * 1024
CONFIG_PATH = "config.ini"
CHUNK_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT = 60

COMMENT_CHARS = frozenset("!#;/[")
HOSTS_IPS = frozenset(("127.0.0.1", "0.0.0.0"))
HOSTS_SAMPLE = 30

logger = logging.getLogger("cfpihole")


def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_urls, tld_url)."""
    config = configparser.ConfigParser(interpolation=None)
    try:
        read = config.read(CONFIG_PATH)
    except configparser.Error as e:
        sys.exit(f"Invalid {CONFIG_PATH}: {e}")
    if not read:
        sys.exit(f"Config file not found: {CONFIG_PATH}")

    block_urls = list(config["BlockLists"].values()) if "BlockLists" in config else []
    tld_urls = list(config["TLDList"].values()) if "TLDList" in config else []

    if not block_urls and not tld_urls:
        sys.exit(f"{CONFIG_PATH} has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        sys.exit("Only one URL is supported in [TLDList]")
    for url in block_urls + tld_urls:
        if not url.startswith("https://"):
            sys.exit(f"URL must use https://: {url}")

    return list(dict.fromkeys(block_urls)), (tld_urls[0] if tld_urls else None)


def download_url(url: str) -> bytes | None:
    """Download a URL. Return None on failure."""
    buffer = bytearray()
    try:
        with requests.get(url, timeout=DOWNLOAD_TIMEOUT, stream=True) as r:
            r.raise_for_status()

            if not r.url.startswith("https://"):
                logger.error("Refused non-HTTPS redirect for %s", highlight(url))
                return None

            for chunk in r.iter_content(CHUNK_BYTES):
                buffer += chunk
                if len(buffer) > MAX_BYTES:
                    logger.error("Refused oversized response for %s", highlight(url))
                    return None

    except requests.RequestException as e:
        logger.error("Failed downloading %s: %s", highlight(url), highlight(e))
        return None

    size = f"{len(buffer) // 1024} KB"
    logger.info("Downloaded: %s %s", highlight(url), highlight(size))
    return bytes(buffer)


def clean_lines(data: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of `data`."""
    lines = (
        line.strip()
        for line in data.decode("utf-8", errors="ignore").lower().splitlines()
    )
    return [line for line in lines if line and line[0] not in COMMENT_CHARS]


def parse_tlds(data: bytes) -> set[str]:
    """Return the set of TLDs found in `data`."""
    tlds = set()
    for line in clean_lines(data):
        tld = "".join(c for c in line if c.isalnum() or c in "-.")
        if tld := tld.strip("."):
            tlds.add(tld)
    return tlds


def parse_domains(data: bytes) -> set[str]:
    """Return the set of domains in a plain-domain list or a hosts file."""
    rows = [line.split() for line in clean_lines(data)]

    sample = rows[:HOSTS_SAMPLE]
    hosts_count = sum(row[0] in HOSTS_IPS for row in sample)
    is_hosts = hosts_count * 2 > len(sample)

    if is_hosts:
        return {
            row[1].rstrip(".")
            for row in rows
            if len(row) > 1 and "localhost" not in row[1]
        }
    return {row[0].rstrip(".") for row in rows}


def download_sources(
    block_urls: list[str], tld_url: str | None
) -> tuple[set[str], set[str], list[str]]:
    """Download and parse everything. Returns (domains, tlds, failed_urls)."""
    with ThreadPoolExecutor() as executor:
        tld_future = executor.submit(download_url, tld_url) if tld_url else None
        block_data = list(executor.map(download_url, block_urls))
    tld_data = tld_future.result() if tld_future else None

    domains: set[str] = set()
    failed = []
    for url, data in zip(block_urls, block_data):
        if data is None:
            failed.append(url)
        else:
            domains |= parse_domains(data)

    tlds: set[str] = set()
    if tld_data is not None:
        tlds = parse_tlds(tld_data)
    elif tld_url:
        failed.append(tld_url)

    return domains, tlds, failed


def main() -> None:
    load_dotenv()
    setup_logging()

    token = os.getenv("CF_API_TOKEN")
    account_id = os.getenv("CF_IDENTIFIER")
    if not token:
        sys.exit("Missing CF_API_TOKEN")
    if not account_id:
        sys.exit("Missing CF_IDENTIFIER")

    session = cloudflare.create_session(token)
    base_url = cloudflare.build_base_url(account_id)

    block_urls, tld_url = load_config()

    all_domains, tlds, failed = download_sources(block_urls, tld_url)
    if failed:
        sys.exit(
            f"{len(failed)} download(s) failed — not modifying Cloudflare: "
            + ", ".join(failed)
        )

    suffixes = tuple("." + t for t in tlds)
    domains = sorted(d for d in all_domains if not d.endswith(suffixes))

    n = cloudflare.MAX_DOMAINS
    chunks = [domains[i : i + n] for i in range(0, len(domains), n)]

    cf_lists = cloudflare.get_items(session, base_url, "lists")
    cloudflare.check_list_limit(cf_lists, len(chunks))

    if domains:
        logger.info(
            "Unique domains: %s → %s lists",
            highlight(len(domains)),
            highlight(len(chunks)),
        )
    else:
        logger.warning("No domains to block — removing existing lists/policy")

    tld_traffic = cloudflare.build_tld_traffic(sorted(tlds)) if tlds else None
    cloudflare.ensure_policy(
        session, base_url, cloudflare.TLD_PREFIX, tld_traffic, True
    )

    cloudflare.sync_lists(session, base_url, chunks, cf_lists)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except cloudflare.CloudflareAPIError as e:
        logger.critical("Cloudflare API error: %s", e)
        sys.exit(64)
    except Exception as e:
        logger.critical("Fatal error: %s", e, exc_info=True)
        sys.exit(1)
