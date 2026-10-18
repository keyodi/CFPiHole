import configparser
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

import cloudflare_api as cloudflare
from logger import setup as setup_logging
from logger import v as highlight

# ─────────────────────────────── Constants ────────────────────────────────

DOMAIN_LIST_PREFIX = "[CFPihole] Block Ads"
TLD_RULE_PREFIX = "[CFPihole] Block TLDs"

MAX_LISTS_PER_ACCOUNT = 300   # Cloudflare Gateway limit
MAX_DOMAINS_PER_LIST = 1000   # Cloudflare Gateway limit

MAX_DOWNLOAD_MB = 10
CONFIG_FILE = "config.ini"
DOWNLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 15

COMMENT_STARTERS = frozenset("!#;/[")
HOSTS_FILE_IPS = frozenset(("127.0.0.1", "0.0.0.0"))
HOSTS_DETECTION_LINES = 30    # Lines inspected to detect hosts-file format

log = logging.getLogger("cfpihole")


# ──────────────────────────────── Config ──────────────────────────────────

def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_list_urls, tld_list_url)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        files_read = parser.read(CONFIG_FILE)
    except configparser.Error as config_error:
        sys.exit(f"Invalid {CONFIG_FILE}: {config_error}")
    if not files_read:
        sys.exit(f"Config file not found: {CONFIG_FILE}")

    def urls_in_section(section: str) -> list[str]:
        return list(parser[section].values()) if section in parser else []

    block_urls = urls_in_section("BlockLists")
    tld_urls = urls_in_section("TLDList")

    if not block_urls and not tld_urls:
        sys.exit(f"{CONFIG_FILE} has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        sys.exit("Only one URL is supported in [TLDList]")
    for url in block_urls + tld_urls:
        if not url.startswith("https://"):
            sys.exit(f"URL must use https://: {url}")

    unique_block_urls = list(dict.fromkeys(block_urls))  # de-dupe, keep order
    tld_url = tld_urls[0] if tld_urls else None
    return unique_block_urls, tld_url


def load_credentials() -> tuple[str, str]:
    """Return (api_token, account_id) from the environment."""
    api_token = os.getenv("CF_API_TOKEN") or sys.exit("Missing CF_API_TOKEN")
    account_id = os.getenv("CF_IDENTIFIER") or sys.exit("Missing CF_IDENTIFIER")
    return api_token, account_id


# ────────────────────────────── Downloading ───────────────────────────────

def download(url: str) -> bytes | None:
    """Download a URL (HTTPS only, size-capped). Returns None on failure."""
    downloaded = bytearray()
    max_bytes = MAX_DOWNLOAD_MB << 20

    try:
        with requests.get(
            url, timeout=DOWNLOAD_TIMEOUT_SECONDS, stream=True
        ) as response:
            response.raise_for_status()

            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", highlight(url))
                return None

            for chunk in response.iter_content(DOWNLOAD_CHUNK_BYTES):
                downloaded += chunk
                if len(downloaded) > max_bytes:
                    log.error(
                        "Refused response over %s MB for %s",
                        highlight(MAX_DOWNLOAD_MB),
                        highlight(url),
                    )
                    return None

    except requests.RequestException as request_error:
        log.error(
            "Failed downloading %s: %s", highlight(url), highlight(request_error)
        )
        return None

    size_kb = f"{len(downloaded) / 1024:.0f} KB"
    log.info("Downloaded: %s %s", highlight(url), highlight(size_kb))
    return bytes(downloaded)


def download_and_parse(url: str, parse) -> set[str] | None:
    """Download `url` and run it through `parse`; None if the download failed."""
    raw_bytes = download(url)
    return None if raw_bytes is None else parse(raw_bytes)


# ──────────────────────────────── Parsing ─────────────────────────────────

def clean_lines(raw_bytes: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of `raw_bytes`."""
    text = raw_bytes.decode("utf-8", errors="ignore").lower()
    stripped_lines = map(str.strip, text.splitlines())
    return [
        line
        for line in stripped_lines
        if line and line[0] not in COMMENT_STARTERS
    ]


def parse_tlds(raw_bytes: bytes) -> set[str]:
    """Return the set of TLDs found in `raw_bytes`."""
    allowed_symbols = "-."
    return {
        tld
        for line in clean_lines(raw_bytes)
        if (
            tld := "".join(
                char for char in line if char.isalnum() or char in allowed_symbols
            ).strip(".")
        )
    }


def parse_domains(raw_bytes: bytes) -> set[str]:
    """Return the set of domains in a plain-domain list or a hosts file."""
    fields_per_line = [line.split() for line in clean_lines(raw_bytes)]

    # Treat it as a hosts file if most of the first lines start with a hosts IP.
    first_fields = [fields[0] for fields in fields_per_line[:HOSTS_DETECTION_LINES]]
    hosts_ip_count = sum(field in HOSTS_FILE_IPS for field in first_fields)
    is_hosts_file = hosts_ip_count * 2 > len(first_fields)

    if is_hosts_file:
        return {
            fields[1].rstrip(".")
            for fields in fields_per_line
            if len(fields) > 1 and "localhost" not in fields[1]
        }
    return {fields[0].rstrip(".") for fields in fields_per_line}


# ───────────────────────────── Cloudflare sync ────────────────────────────

def list_number(list_name: str) -> int:
    """Return the number at the end of '<DOMAIN_LIST_PREFIX> <n>' (odd names last)."""
    try:
        return int(list_name[len(DOMAIN_LIST_PREFIX):])
    except ValueError:
        return sys.maxsize


def sync_domain_lists(
    session, gateway_url, domain_chunks, gateway_rules, gateway_lists
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one rule."""
    existing_lists = sorted(
        cloudflare.with_prefix(gateway_lists, DOMAIN_LIST_PREFIX),
        key=lambda gateway_list: list_number(gateway_list["name"]),
    )

    # Remove lists we no longer need.
    if surplus_lists := existing_lists[len(domain_chunks):]:
        # A list used by a rule can't be deleted, so delete the rule first.
        cloudflare.ensure_rule(
            session, gateway_url, gateway_rules, DOMAIN_LIST_PREFIX, None, False
        )
        gateway_rules = []
        cloudflare.delete(session, gateway_url, "lists", surplus_lists)

    # Create or update one list per chunk, reusing existing list IDs.
    if domain_chunks:
        log.info("Updating lists, please wait")

    list_ids = [
        cloudflare.save_list(
            session,
            gateway_url,
            f"{DOMAIN_LIST_PREFIX} {list_position}",
            domains_in_chunk,
            (
                existing_lists[list_position - 1]["id"]
                if list_position <= len(existing_lists)
                else None
            ),
        )
        for list_position, domains_in_chunk in enumerate(domain_chunks, start=1)
    ]

    # Point the rule at the fresh lists (or remove it if there are none).
    rule_traffic = cloudflare.domain_traffic(list_ids) if list_ids else None
    cloudflare.ensure_rule(
        session, gateway_url, gateway_rules, DOMAIN_LIST_PREFIX, rule_traffic, False
    )


# ──────────────────────────────── Pipeline ────────────────────────────────

def collect(
    block_urls: list[str], tld_url: str | None
) -> tuple[set[str], list[str], set[str] | None]:
    """Download everything in parallel. Returns domains, failed_block_urls, tlds"""
    with ThreadPoolExecutor() as pool:
        tld_future = (
            pool.submit(download_and_parse, tld_url, parse_tlds)
            if tld_url
            else None
        )
        domains_per_url = list(
            pool.map(lambda url: download_and_parse(url, parse_domains), block_urls)
        )

    failed_urls = [
        url for url, domains in zip(block_urls, domains_per_url) if domains is None
    ]
    all_domains = set().union(
        *(domains for domains in domains_per_url if domains is not None)
    )
    tlds = tld_future.result() if tld_future else set()

    return all_domains, failed_urls, tlds


def main() -> None:
    load_dotenv()
    setup_logging()

    api_token, account_id = load_credentials()
    gateway_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
    )
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {api_token}"

    block_urls, tld_url = load_config()

    # 1. Download and parse every list.
    all_domains, failed_urls, tlds = collect(block_urls, tld_url)

    if failed_urls:
        log.warning(
            "Skipping %s failed download(s): %s",
            highlight(len(failed_urls)),
            highlight(", ".join(failed_urls)),
        )
    if tld_url and tlds is None:
        log.warning("TLD list unavailable — no TLD-level blocking this run")
    tlds = tlds or set()

    # Domains already covered by a blocked TLD don't need their own entry.
    tld_suffixes = tuple("." + tld for tld in tlds)
    domains_to_block = sorted(
        domain for domain in all_domains if not domain.endswith(tld_suffixes)
    )

    if failed_urls and not domains_to_block:
        sys.exit("All block-list downloads failed — not modifying Cloudflare")

    # 2. Read current Cloudflare state.
    gateway_rules = cloudflare.get_all(session, gateway_url, "rules")
    gateway_lists = cloudflare.get_all(session, gateway_url, "lists")

    # 3. Sync the TLD rule.
    tld_rule_traffic = cloudflare.tld_traffic(sorted(tlds)) if tlds else None
    cloudflare.ensure_rule(
        session, gateway_url, gateway_rules, TLD_RULE_PREFIX, tld_rule_traffic, True
    )

    # 4. Split domains into list-sized chunks and check the account limit.
    domain_chunks = [
        domains_to_block[start:start + MAX_DOMAINS_PER_LIST]
        for start in range(0, len(domains_to_block), MAX_DOMAINS_PER_LIST)
    ]

    # Lists that aren't ours still count towards Cloudflare's limit.
    our_list_count = len(cloudflare.with_prefix(gateway_lists, DOMAIN_LIST_PREFIX))
    other_list_count = len(gateway_lists) - our_list_count
    if len(domain_chunks) + other_list_count > MAX_LISTS_PER_ACCOUNT:
        sys.exit(
            f"Would exceed {MAX_LISTS_PER_ACCOUNT} list limit "
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

    # 5. Sync the domain lists and rule.
    sync_domain_lists(
        session, gateway_url, domain_chunks, gateway_rules, gateway_lists
    )


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
