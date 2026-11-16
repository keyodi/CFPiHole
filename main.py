import configparser
import logging
import os
import sys

import requests
from dotenv import load_dotenv

import cloudflare_api as cloudflare
from logger import highlight, setup_logging

MAX_BYTES = 10 * 1024 * 1024
CONFIG_PATH = "config.ini"
CHUNK_SIZE = 64 * 1024
DOWNLOAD_TIMEOUT = 60
MAX_RETRIES = 3

COMMENT_CHARS = frozenset("!#;/[")
HOSTS_IPS = frozenset(("127.0.0.1", "0.0.0.0"))
HOSTS_SAMPLE = 30

logger = logging.getLogger("cfpihole")


def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_urls, tld_url)."""
    config = configparser.ConfigParser(interpolation=None)
    if not config.read(CONFIG_PATH):
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

    return list(dict.fromkeys(block_urls)), tld_urls[0] if tld_urls else None


def download_url(url: str) -> bytes | None:
    """Download a URL, retrying request exceptions up to MAX_RETRIES times."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            with requests.get(url, timeout=DOWNLOAD_TIMEOUT, stream=True) as response:
                response.raise_for_status()

                if not response.url.startswith("https://"):
                    logger.error(f"Refused non-HTTPS redirect for {highlight(url)}")
                    return None

                buffer = bytearray()
                for chunk in response.iter_content(CHUNK_SIZE):
                    buffer.extend(chunk)
                    if len(buffer) > MAX_BYTES:
                        logger.error(f"Refused oversized response for {highlight(url)}")
                        return None

        except requests.RequestException as exc:
            logger.error(f"Failed downloading {highlight(url)}: {highlight(exc)}")
            if attempt < MAX_RETRIES:
                logger.warning(
                    f"Retrying download for {highlight(url)} "
                    f"(retry {attempt + 1}/{MAX_RETRIES})"
                )
                continue
            return None

        logger.info(
            f"Downloaded: {highlight(url)} {highlight(f'{len(buffer) // 1024} KB')}"
        )
        return bytes(buffer)

    return None


def clean_lines(data: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of `data`."""
    return [
        line.strip()
        for line in data.decode("utf-8", errors="ignore").lower().splitlines()
        if line.strip() and line.strip()[0] not in COMMENT_CHARS
    ]


def parse_tlds(data: bytes) -> set[str]:
    """Return the set of TLDs found in `data`."""
    tlds: set[str] = set()
    for line in clean_lines(data):
        tld = "".join(ch for ch in line if ch.isalnum() or ch in "-.")
        tld = tld.strip(".")
        if tld:
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

    return {row[0].rstrip(".") for row in rows if row}


def download_sources(
    block_urls: list[str], tld_url: str | None
) -> tuple[set[str], set[str], list[str]]:
    """Download and parse everything. Returns (domains, tlds, failed_urls)."""
    domains: set[str] = set()
    tlds: set[str] = set()
    failed: list[str] = []

    for url in block_urls:
        data = download_url(url)
        if data is None:
            failed.append(url)
        else:
            domains |= parse_domains(data)

    if tld_url:
        data = download_url(tld_url)
        if data is None:
            failed.append(tld_url)
        else:
            tlds = parse_tlds(data)

    return domains, tlds, failed


def main() -> None:
    """Main entry point."""
    load_dotenv()
    setup_logging()

    token = os.getenv("CF_API_TOKEN")
    account_id = os.getenv("CF_IDENTIFIER")
    if not token:
        sys.exit("Missing CF_API_TOKEN")
    if not account_id:
        sys.exit("Missing CF_IDENTIFIER")

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    base_url = f"{cloudflare.API_URL}/accounts/{account_id}/gateway"

    block_urls, tld_url = load_config()
    all_domains, tlds, failed = download_sources(block_urls, tld_url)

    if failed:
        sys.exit(
            f"{len(failed)} download(s) failed — not modifying Cloudflare: "
            f"{', '.join(failed)}"
        )

    suffixes = tuple("." + t for t in tlds)
    domains = sorted(d for d in all_domains if not d.endswith(suffixes))

    chunks = [
        domains[i : i + cloudflare.MAX_DOMAINS]
        for i in range(0, len(domains), cloudflare.MAX_DOMAINS)
    ]

    cf_lists = cloudflare.get_items(session, base_url, "lists")
    if domains:
        logger.info(
            f"Unique domains: {highlight(len(domains))} → {highlight(len(chunks))} lists"
        )
    else:
        logger.warning("No domains to block — removing existing lists/policy")

    if not cloudflare.check_list_limit(cf_lists, len(chunks)):
        logger.info(
            f"More than {highlight(cloudflare.MAX_LISTS)} Cloudflare lists would be needed; "
            "stopping without changes"
        )
        return

    tld_traffic = cloudflare.build_tld_traffic(sorted(tlds)) if tlds else None
    cloudflare.ensure_policy(session, base_url, cloudflare.TLD_PREFIX, tld_traffic, True)
    cloudflare.sync_lists(session, base_url, chunks, cf_lists)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except cloudflare.CloudflareAPIError as exc:
        logger.critical(f"Critical Cloudflare API error: {exc}")
        sys.exit(64)
    except Exception as exc:
        logger.critical(f"Fatal error: {exc}", exc_info=True)
        sys.exit(1)
