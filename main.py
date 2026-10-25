import configparser
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

import cloudflare_api as cloudflare
from logger import highlight, setup_logging

AD_BLOCK_PREFIX = "[CFPiHole] Block Ads"
TLD_BLOCK_PREFIX = "[CFPiHole] Block TLDs"

MAX_GATEWAY_LISTS = 300
MAX_DOMAINS_PER_LIST = 1000

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
CONFIG_FILE = "config.ini"
DOWNLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60

COMMENT_STARTERS = frozenset("!#;/[")
HOSTS_FILE_IPS = frozenset(("127.0.0.1", "0.0.0.0"))
HOST_SAMPLE_LINES = 30

log = logging.getLogger("cfpihole")


def load_list_sources() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_list_urls, tld_list_url)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        files_read = parser.read(CONFIG_FILE)
    except configparser.Error as config_error:
        sys.exit(f"Invalid {CONFIG_FILE}: {config_error}")
    if not files_read:
        sys.exit(f"Config file not found: {CONFIG_FILE}")

    block_urls = list(parser["BlockLists"].values()) if "BlockLists" in parser else []
    tld_urls = list(parser["TLDList"].values()) if "TLDList" in parser else []

    if not block_urls and not tld_urls:
        sys.exit(f"{CONFIG_FILE} has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        sys.exit("Only one URL is supported in [TLDList]")
    for url in block_urls + tld_urls:
        if not url.startswith("https://"):
            sys.exit(f"URL must use https://: {url}")

    unique_block_urls = list(dict.fromkeys(block_urls))
    return unique_block_urls, (tld_urls[0] if tld_urls else None)


def fetch_url(url: str) -> bytes | None:
    """Download a URL. Return None on failure."""
    downloaded = bytearray()
    try:
        with requests.get(url, timeout=DOWNLOAD_TIMEOUT_SECONDS, stream=True) as response:
            response.raise_for_status()

            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", highlight(url))
                return None

            for chunk in response.iter_content(DOWNLOAD_CHUNK_BYTES):
                downloaded += chunk
                if len(downloaded) > MAX_DOWNLOAD_BYTES:
                    log.error("Refused oversized response for %s", highlight(url))
                    return None

    except requests.RequestException as request_error:
        log.error(
            "Failed downloading %s: %s",
            highlight(url),
            highlight(request_error),
        )
        return None

    size_kb = f"{len(downloaded) // 1024} KB"
    log.info("Downloaded: %s %s", highlight(url), highlight(size_kb))
    return bytes(downloaded)


def clean_lines(raw_bytes: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of `raw_bytes`."""
    text = raw_bytes.decode("utf-8", errors="ignore").lower()
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and line[0] not in COMMENT_STARTERS]


def extract_tlds(raw_bytes: bytes) -> set[str]:
    """Return the set of TLDs found in `raw_bytes`."""
    tlds = set()
    for line in clean_lines(raw_bytes):
        tld = "".join(char for char in line if char.isalnum() or char in "-.")
        if tld := tld.strip("."):
            tlds.add(tld)
    return tlds


def extract_domains(raw_bytes: bytes) -> set[str]:
    """Return the set of domains in a plain-domain list or a hosts file."""
    rows = [line.split() for line in clean_lines(raw_bytes)]

    sample = rows[:HOST_SAMPLE_LINES]
    hosts_ip_rows = sum(row[0] in HOSTS_FILE_IPS for row in sample)
    is_hosts_file = hosts_ip_rows * 2 > len(sample)

    if is_hosts_file:
        return {
            row[1].rstrip(".")
            for row in rows
            if len(row) > 1 and "localhost" not in row[1]
        }
    return {row[0].rstrip(".") for row in rows}


def sync_gateway_lists(
    session: requests.Session,
    gateway_url: str,
    domain_chunks: list[list[str]],
    gateway_lists: list[dict],
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one rule."""
    existing_by_name = {
        gateway_list["name"]: gateway_list
        for gateway_list in cloudflare.with_prefix(gateway_lists, AD_BLOCK_PREFIX)
    }
    wanted_names = [
        f"{AD_BLOCK_PREFIX} {number}" for number in range(1, len(domain_chunks) + 1)
    ]

    surplus_lists = [
        gateway_list
        for name, gateway_list in existing_by_name.items()
        if name not in wanted_names
    ]
    if surplus_lists:
        cloudflare.ensure_rule(session, gateway_url, AD_BLOCK_PREFIX, None, False)
        cloudflare.delete(session, gateway_url, "lists", surplus_lists)

    if domain_chunks:
        log.info("Updating lists, please wait")

    list_ids = []
    for name, domains in zip(wanted_names, domain_chunks):
        existing_list = existing_by_name.get(name)
        existing_id = existing_list["id"] if existing_list else None
        list_ids.append(
            cloudflare.save_list(session, gateway_url, name, domains, existing_id)
        )

    rule_traffic = cloudflare.domain_traffic(list_ids) if list_ids else None
    cloudflare.ensure_rule(
        session, gateway_url, AD_BLOCK_PREFIX, rule_traffic, False
    )


def fetch_and_parse_lists(
    block_urls: list[str], tld_url: str | None
) -> tuple[set[str], set[str], list[str]]:
    """Download and parse everything. Returns (domains, tlds, failed_urls)."""
    with ThreadPoolExecutor() as pool:
        tld_future = pool.submit(fetch_url, tld_url) if tld_url else None
        block_downloads = list(pool.map(fetch_url, block_urls))
    tld_bytes = tld_future.result() if tld_future else None

    all_domains: set[str] = set()
    failed_urls = []
    for url, raw_bytes in zip(block_urls, block_downloads):
        if raw_bytes is None:
            failed_urls.append(url)
        else:
            all_domains |= extract_domains(raw_bytes)

    tlds: set[str] = set()
    if tld_bytes is not None:
        tlds = extract_tlds(tld_bytes)
    elif tld_url:
        failed_urls.append(tld_url)

    return all_domains, tlds, failed_urls


def main() -> None:
    load_dotenv()
    setup_logging()

    api_token = os.getenv("CF_API_TOKEN")
    account_id = os.getenv("CF_IDENTIFIER")
    if not api_token:
        sys.exit("Missing CF_API_TOKEN")
    if not account_id:
        sys.exit("Missing CF_IDENTIFIER")

    gateway_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {api_token}"

    block_urls, tld_url = load_list_sources()

    all_domains, tlds, failed_urls = fetch_and_parse_lists(block_urls, tld_url)
    if failed_urls:
        sys.exit(
            f"{len(failed_urls)} download(s) failed — not modifying Cloudflare: "
            + ", ".join(failed_urls)
        )

    tld_suffixes = tuple("." + tld for tld in tlds)
    domains_to_block = sorted(
        domain for domain in all_domains if not domain.endswith(tld_suffixes)
    )

    domain_chunks = [
        domains_to_block[start : start + MAX_DOMAINS_PER_LIST]
        for start in range(0, len(domains_to_block), MAX_DOMAINS_PER_LIST)
    ]

    gateway_lists = cloudflare.get_all(session, gateway_url, "lists")
    our_list_count = len(cloudflare.with_prefix(gateway_lists, AD_BLOCK_PREFIX))
    other_list_count = len(gateway_lists) - our_list_count
    if len(domain_chunks) + other_list_count > MAX_GATEWAY_LISTS:
        sys.exit(
            f"Would exceed {MAX_GATEWAY_LISTS} list limit "
            "— use smaller block lists"
        )

    if domains_to_block:
        log.info(
            "Unique domains: %s → %s lists",
            highlight(len(domains_to_block)),
            highlight(len(domain_chunks)),
        )
    else:
        log.warning("No domains to block — removing existing lists/rule")

    tld_rule_traffic = cloudflare.tld_traffic(sorted(tlds)) if tlds else None
    cloudflare.ensure_rule(
        session, gateway_url, TLD_BLOCK_PREFIX, tld_rule_traffic, True
    )

    sync_gateway_lists(session, gateway_url, domain_chunks, gateway_lists)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except cloudflare.CloudflareAPIError as api_error:
        log.critical("Cloudflare API error: %s", api_error)
        sys.exit(64)
    except Exception as unexpected_error:
        log.critical("Fatal error: %s", unexpected_error, exc_info=True)
        sys.exit(1)
