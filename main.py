import configparser
import logging
import os
import sys

import requests
from dotenv import load_dotenv

import cloudflare_api as cf
from logger import setup as setup_logging
from logger import v

CONFIG_FILE = "config.ini"
DOMAIN_NAME_PREFIX = "[CFPihole] Block Ads"
TLD_NAME_PREFIX = "[CFPihole] Block TLDs"

# Cloudflare Gateway limits
MAX_LISTS = 300
DOMAINS_PER_LIST = 1000

DOWNLOAD_TIMEOUT_SECONDS = 15
DOWNLOAD_CHUNK_BYTES = 65536
MAX_DOWNLOAD_MB = 10
MAX_DOWNLOAD_BYTES = MAX_DOWNLOAD_MB * 1024 * 1024

COMMENT_CHARS = frozenset("!#;/[")
HOSTS_FILE_IPS = frozenset(("127.0.0.1", "0.0.0.0"))
HOSTS_DETECTION_LINES = 30

log = logging.getLogger("cfpihole")


def require_env(name: str) -> str:
    """Return an environment variable or exit if it is missing."""
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing {name}")
    return value


def section_urls(parser: configparser.ConfigParser, section: str) -> list[str]:
    """Return the URLs in a config section (empty if it is missing)."""
    if section not in parser:
        return []
    return list(parser[section].values())


def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_list_urls, tld_list_url)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        files_read = parser.read(CONFIG_FILE)
    except configparser.Error as error:
        raise SystemExit(f"Invalid config.ini: {error}")
    if not files_read:
        raise SystemExit(f"Config file not found: {CONFIG_FILE}")

    block_urls = section_urls(parser, "BlockLists")
    tld_urls = section_urls(parser, "TLDList")

    if not block_urls and not tld_urls:
        raise SystemExit("config.ini has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        raise SystemExit("Only one URL is supported in [TLDList]")
    for url in block_urls + tld_urls:
        if not url.startswith("https://"):
            raise SystemExit(f"URL must use https://: {url}")

    block_urls = list(dict.fromkeys(block_urls))  # drop duplicates, keep order
    tld_url = tld_urls[0] if tld_urls else None
    return block_urls, tld_url


def download(url: str) -> bytes | None:
    """Download a URL and return its bytes, or None on failure."""
    downloaded = bytearray()
    try:
        with requests.get(
            url, timeout=DOWNLOAD_TIMEOUT_SECONDS, stream=True
        ) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", v(url))
                return None

            for chunk in response.iter_content(DOWNLOAD_CHUNK_BYTES):
                downloaded += chunk
                if len(downloaded) > MAX_DOWNLOAD_BYTES:
                    log.error(
                        "Refused response over %s MB for %s",
                        v(MAX_DOWNLOAD_MB),
                        v(url),
                    )
                    return None
    except requests.RequestException as error:
        log.error("Failed downloading %s: %s", v(url), v(error))
        return None

    size_kb = len(downloaded) / 1024
    log.info("Downloaded: %s %s", v(url), v(f"{size_kb:.0f} KB"))
    return bytes(downloaded)


def clean_lines(raw_bytes: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of raw_bytes."""
    text = raw_bytes.decode("utf-8", errors="ignore").lower()
    stripped_lines = (line.strip() for line in text.splitlines())
    return [
        line
        for line in stripped_lines
        if line and line[0] not in COMMENT_CHARS
    ]


def parse_tlds(raw_bytes: bytes) -> set[str]:
    """Return the set of TLDs found in raw_bytes."""
    tlds = set()
    for line in clean_lines(raw_bytes):
        tld = "".join(
            char for char in line if char.isalnum() or char in "-."
        ).strip(".")
        if tld:
            tlds.add(tld)
    return tlds


def parse_domains(raw_bytes: bytes) -> set[str]:
    """Return the set of domains found in raw_bytes."""
    lines = clean_lines(raw_bytes)

    # Treat the file as a hosts file if most of its first lines start
    # with a hosts IP address.
    first_words = [line.split()[0] for line in lines[:HOSTS_DETECTION_LINES]]
    hosts_line_count = sum(word in HOSTS_FILE_IPS for word in first_words)
    is_hosts_file = hosts_line_count * 2 > len(first_words)

    domains = set()
    for line in lines:
        words = line.split()
        if not is_hosts_file:
            domains.add(words[0].rstrip("."))
        elif len(words) >= 2 and "localhost" not in words[1]:
            domains.add(words[1].rstrip("."))
    return domains


def drop_blocked_tlds(domains: set[str], tlds: set[str]) -> set[str]:
    """Remove domains already covered by the TLD rule."""
    tld_suffixes = tuple("." + tld for tld in tlds)
    return {
        domain for domain in domains if not domain.endswith(tld_suffixes)
    }


def fetch(url: str, parse) -> set[str] | None:
    """Download and parse a URL, or return None if the download failed."""
    raw_bytes = download(url)
    return None if raw_bytes is None else parse(raw_bytes)


def list_number(list_name: str) -> int:
    """Number at the end of '<DOMAIN_NAME_PREFIX> <n>' (odd names last)."""
    try:
        return int(list_name[len(DOMAIN_NAME_PREFIX):])
    except ValueError:
        return sys.maxsize


def sync_tld_rule(
    session: requests.Session,
    gateway_url: str,
    account_rules: list[cf.JsonDict],
    blocked_tlds: set[str],
) -> None:
    """Make Cloudflare hold the TLD rule for blocked_tlds (none if empty)."""
    existing_rules = cf.with_prefix(account_rules, TLD_NAME_PREFIX)
    sorted_tlds = sorted(blocked_tlds)  # keeps the expression stable
    traffic = cf.tld_traffic(sorted_tlds)

    if (
        sorted_tlds
        and len(existing_rules) == 1
        and cf.rule_matches(
            existing_rules[0], traffic, block_page_enabled=True
        )
    ):
        log.info("TLD rule unchanged — skipping")
        return

    cf.delete_rules(session, gateway_url, existing_rules)
    if sorted_tlds:
        cf.create_rule(
            session,
            gateway_url,
            TLD_NAME_PREFIX,
            traffic,
            block_page_enabled=True,
        )


def sync_domain_lists(
    session: requests.Session,
    gateway_url: str,
    domain_chunks: list[list[str]],
    account_rules: list[cf.JsonDict],
    account_lists: list[cf.JsonDict],
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one rule."""
    existing_lists = sorted(
        cf.with_prefix(account_lists, DOMAIN_NAME_PREFIX),
        key=lambda gateway_list: list_number(gateway_list["name"]),
    )
    lists_to_update = existing_lists[: len(domain_chunks)]
    lists_to_delete = existing_lists[len(domain_chunks):]
    domain_rules = cf.with_prefix(account_rules, DOMAIN_NAME_PREFIX)

    if lists_to_delete:
        # A list used by a rule can't be deleted, so delete the rule first.
        cf.delete_rules(session, gateway_url, domain_rules)
        domain_rules = []
        cf.delete_lists(session, gateway_url, lists_to_delete)

    log.info("Updating lists, please wait")
    list_ids = []
    for position, domain_chunk in enumerate(domain_chunks, start=1):
        list_name = f"{DOMAIN_NAME_PREFIX} {position}"
        if position <= len(lists_to_update):
            list_id = lists_to_update[position - 1]["id"]
            cf.update_list(
                session, gateway_url, list_id, list_name, domain_chunk
            )
        else:
            list_id = cf.create_list(
                session, gateway_url, list_name, domain_chunk
            )
        list_ids.append(list_id)

    traffic = cf.domain_traffic(list_ids)
    if len(domain_rules) == 1 and cf.rule_matches(
        domain_rules[0], traffic, block_page_enabled=False
    ):
        log.info("Domain rule unchanged — skipping")
        return

    cf.delete_rules(session, gateway_url, domain_rules)
    cf.create_rule(
        session,
        gateway_url,
        DOMAIN_NAME_PREFIX,
        traffic,
        block_page_enabled=False,
    )


def main() -> None:
    load_dotenv()
    setup_logging()

    api_token = require_env("CF_API_TOKEN")
    account_id = require_env("CF_IDENTIFIER")
    gateway_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
    )

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {api_token}"

    block_urls, tld_url = load_config()

    # Block lists: collect the domains, skipping any that failed to download.
    blocked_domains: set[str] = set()
    failed_urls = []
    for url in block_urls:
        domains = fetch(url, parse_domains)
        if domains is None:
            failed_urls.append(url)
        else:
            blocked_domains |= domains
    if failed_urls:
        log.warning(
            "Skipping %s failed download(s): %s",
            v(len(failed_urls)),
            v(", ".join(failed_urls)),
        )

    # TLD list: if it failed, no TLD rule is kept this run.
    downloaded_tlds = fetch(tld_url, parse_tlds) if tld_url else None
    if tld_url and downloaded_tlds is None:
        log.warning("TLD list unavailable — no TLD-level blocking this run")
    blocked_tlds = downloaded_tlds or set()

    blocked_domains = drop_blocked_tlds(blocked_domains, blocked_tlds)

    if failed_urls and not blocked_domains:
        raise SystemExit(
            "All block-list downloads failed — not modifying Cloudflare"
        )

    account_rules = cf.get_all(session, gateway_url, "rules")
    account_lists = cf.get_all(session, gateway_url, "lists")

    sync_tld_rule(session, gateway_url, account_rules, blocked_tlds)

    our_lists = cf.with_prefix(account_lists, DOMAIN_NAME_PREFIX)

    if not blocked_domains:
        log.warning("No domains to block — removing existing lists/rule")
        our_rules = cf.with_prefix(account_rules, DOMAIN_NAME_PREFIX)
        cf.delete_rules(session, gateway_url, our_rules)
        cf.delete_lists(session, gateway_url, our_lists)
        return

    sorted_domains = sorted(blocked_domains)
    domain_chunks = [
        sorted_domains[start : start + DOMAINS_PER_LIST]
        for start in range(0, len(sorted_domains), DOMAINS_PER_LIST)
    ]

    # Lists that aren't ours still count towards Cloudflare's limit.
    other_list_count = len(account_lists) - len(our_lists)
    if len(domain_chunks) + other_list_count > MAX_LISTS:
        raise SystemExit(
            f"Would exceed {MAX_LISTS} list limit — use smaller block lists"
        )

    log.info(
        "Unique domains: %s → %s lists",
        v(len(sorted_domains)),
        v(len(domain_chunks)),
    )

    sync_domain_lists(
        session, gateway_url, domain_chunks, account_rules, account_lists
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except cf.CloudflareAPIError as error:
        log.critical("Cloudflare API error: %s", error)
        raise SystemExit(64)
    except Exception as error:
        log.critical("Fatal error: %s", error, exc_info=True)
        raise SystemExit(1)
