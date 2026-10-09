import configparser
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

import cloudflare_api as cf
from logger import setup as setup_logging
from logger import v

CONFIG_FILE = "config.ini"
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"

# Cloudflare Gateway limits
MAX_LISTS = 300
CHUNK_SIZE = 1000

MAX_DOWNLOAD_MB = 10
MAX_DOWNLOAD_BYTES = MAX_DOWNLOAD_MB * 1024 * 1024
MAX_DOWNLOAD_WORKERS = 16

COMMENT_CHARS = frozenset("!#;/[")
HOSTS_IPS = frozenset(("127.0.0.1", "0.0.0.0"))

log = logging.getLogger("cfpihole")


def require_env(name: str) -> str:
    """Return an environment variable or exit if it is missing."""
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing {name}")
    return value


def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_list_urls, tld_list_url)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        found = parser.read(CONFIG_FILE)
    except configparser.Error as exc:
        raise SystemExit(f"Invalid config.ini: {exc}")
    if not found:
        raise SystemExit(f"Config file not found: {CONFIG_FILE}")

    block_urls = list(parser["BlockLists"].values()) if "BlockLists" in parser else []
    tld_urls = list(parser["TLDList"].values()) if "TLDList" in parser else []

    if not block_urls and not tld_urls:
        raise SystemExit("config.ini has no [BlockLists] or [TLDList] entries")
    if len(tld_urls) > 1:
        raise SystemExit("Only one URL is supported in [TLDList]")
    for url in block_urls + tld_urls:
        if not url.startswith("https://"):
            raise SystemExit(f"URL must use https://: {url}")

    unique_block_urls = list(dict.fromkeys(block_urls))  # drop duplicates, keep order
    return unique_block_urls, (tld_urls[0] if tld_urls else None)


def download(url: str) -> bytes | None:
    """Download a URL and return its bytes, or None on failure."""
    content = bytearray()
    try:
        with requests.get(url, timeout=15, stream=True) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", v(url))
                return None

            for part in response.iter_content(chunk_size=65536):
                content += part
                if len(content) > MAX_DOWNLOAD_BYTES:
                    log.error(
                        "Refused response over %s MB for %s",
                        v(MAX_DOWNLOAD_MB),
                        v(url),
                    )
                    return None
    except requests.RequestException as exc:
        log.error("Failed downloading %s: %s", v(url), v(exc))
        return None

    log.info("Downloaded: %s %s", v(url), v(f"{len(content) / 1024:.0f} KB"))
    return bytes(content)


def clean_lines(raw: bytes) -> list[str]:
    """Return the non-empty, non-comment, lower-cased lines of raw bytes."""
    text = raw.decode("utf-8", errors="ignore").lower()
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and line[0] not in COMMENT_CHARS]


def parse_tlds(raw: bytes) -> set[str]:
    """Return the set of TLDs found in raw bytes."""
    tlds = set()
    for line in clean_lines(raw):
        tld = "".join(c for c in line if c.isalnum() or c in "-.").strip(".")
        if tld:
            tlds.add(tld)
    return tlds


def parse_domains(raw: bytes) -> set[str]:
    """Return the set of domains found in raw bytes.

    Handles both plain domain lists and hosts files ("0.0.0.0 example.com").
    """
    lines = clean_lines(raw)

    # Treat the file as a hosts file if most of its first 30 lines start
    # with a hosts IP address.
    first_words = [line.split()[0] for line in lines[:30]]
    hosts_lines = sum(word in HOSTS_IPS for word in first_words)
    is_hosts_file = hosts_lines * 2 > len(first_words)

    if is_hosts_file:
        domains = set()
        for line in lines:
            words = line.split()
            if len(words) >= 2 and "localhost" not in words[1]:
                domains.add(words[1].rstrip("."))
        return domains

    return {line.split()[0].rstrip(".") for line in lines}


def drop_blocked_tlds(domains: set[str], tlds: set[str]) -> set[str]:
    """Remove domains already covered by the TLD rule."""
    single = {tld for tld in tlds if "." not in tld}
    multi = tuple("." + tld for tld in tlds if "." in tld)

    def is_blocked(domain: str) -> bool:
        if "." not in domain:
            return False
        return domain.rpartition(".")[2] in single or domain.endswith(multi)

    return {domain for domain in domains if not is_blocked(domain)}


def fetch(url: str, parse) -> set[str] | None:
    """Download and parse a URL (run in a worker thread)."""
    raw = download(url)
    return None if raw is None else parse(raw)


def list_number(name: str) -> int:
    """Number at the end of '<NAME_PREFIX> <n>' (odd names sort last)."""
    try:
        return int(name[len(NAME_PREFIX) :])
    except ValueError:
        return sys.maxsize


def sync_tld_rule(
    session: requests.Session,
    base: str,
    all_rules: list[cf.JsonDict],
    tld_set: set[str],
) -> None:
    """Make Cloudflare hold the TLD rule for tld_set (or none if it's empty)."""
    existing = cf.rules_with_prefix(all_rules, NAME_PREFIX_TLD)
    tlds = sorted(tld_set)  # sorted, so the expression is stable and comparable
    traffic = cf.tld_traffic(tlds)

    if (
        tlds
        and len(existing) == 1
        and cf.rule_matches(existing[0], traffic, block_page_enabled=True)
    ):
        log.info("TLD rule unchanged — skipping")
        return

    cf.delete_rules(session, base, existing)
    if tlds:
        cf.create_rule(
            session, base, NAME_PREFIX_TLD, traffic, block_page_enabled=True
        )


def sync_domain_lists(
    session: requests.Session,
    base: str,
    chunks: list[list[str]],
    all_rules: list[cf.JsonDict],
    all_lists: list[cf.JsonDict],
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one rule."""
    existing = sorted(
        cf.lists_with_prefix(all_lists, NAME_PREFIX),
        key=lambda item: list_number(item["name"]),
    )
    reused, surplus = existing[: len(chunks)], existing[len(chunks) :]
    domain_rules = cf.rules_with_prefix(all_rules, NAME_PREFIX)

    if surplus:
        # A list used by a rule can't be deleted, so delete the rule first.
        cf.delete_rules(session, base, domain_rules)
        domain_rules = []
        cf.delete_lists(session, base, surplus)

    log.info("Updating lists, please wait")
    list_ids = []
    for number, chunk in enumerate(chunks, 1):
        name = f"{NAME_PREFIX} {number}"
        if number <= len(reused):
            list_id = reused[number - 1]["id"]
            cf.update_list(session, base, list_id, name, chunk)
        else:
            list_id = cf.create_list(session, base, name, chunk)
        list_ids.append(list_id)

    traffic = cf.domain_traffic(list_ids)
    if len(domain_rules) == 1 and cf.rule_matches(
        domain_rules[0], traffic, block_page_enabled=False
    ):
        log.info("Domain rule unchanged — skipping")
        return

    cf.delete_rules(session, base, domain_rules)
    cf.create_rule(session, base, NAME_PREFIX, traffic, block_page_enabled=False)


def main() -> None:
    load_dotenv()
    setup_logging()

    token = require_env("CF_API_TOKEN")
    account_id = require_env("CF_IDENTIFIER")
    base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"

    block_urls, tld_url = load_config()

    # Fetch everything at once: Cloudflare's rules and lists, every block
    # list, and the TLD list.
    workers = min(len(block_urls) + 3, MAX_DOWNLOAD_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rules_future = pool.submit(cf.get_rules, session, base)
        lists_future = pool.submit(cf.get_lists, session, base)
        block_futures = {
            url: pool.submit(fetch, url, parse_domains) for url in block_urls
        }
        tld_future = pool.submit(fetch, tld_url, parse_tlds) if tld_url else None

    # Block lists: collect the domains, skipping any that failed to download.
    block_results = {url: fut.result() for url, fut in block_futures.items()}
    failed_urls = [url for url, domains in block_results.items() if domains is None]
    if failed_urls:
        log.warning(
            "Skipping %s failed download(s): %s",
            v(len(failed_urls)),
            v(", ".join(failed_urls)),
        )

    # TLD list: if it failed, no TLD rule is kept this run.
    tld_result = tld_future.result() if tld_future else None
    tld_set = tld_result or set()
    if tld_future and tld_result is None:
        log.warning("TLD list unavailable — no TLD-level blocking this run")

    all_domains = set().union(*(d for d in block_results.values() if d is not None))
    all_domains = drop_blocked_tlds(all_domains, tld_set)

    if failed_urls and not all_domains:
        raise SystemExit(
            "All block-list downloads failed — not modifying Cloudflare"
        )

    all_rules = rules_future.result()
    all_lists = lists_future.result()

    sync_tld_rule(session, base, all_rules, tld_set)

    if not all_domains:
        log.warning("No domains to block — removing existing lists/rule")
        cf.delete_rules(session, base, cf.rules_with_prefix(all_rules, NAME_PREFIX))
        cf.delete_lists(session, base, cf.lists_with_prefix(all_lists, NAME_PREFIX))
        return

    sorted_domains = sorted(all_domains)
    chunks = [
        sorted_domains[i : i + CHUNK_SIZE]
        for i in range(0, len(sorted_domains), CHUNK_SIZE)
    ]

    # Lists that aren't ours still count towards Cloudflare's limit.
    other_lists = len(all_lists) - len(cf.lists_with_prefix(all_lists, NAME_PREFIX))
    if len(chunks) + other_lists > MAX_LISTS:
        raise SystemExit(f"Would exceed {MAX_LISTS} list limit — use smaller block lists")

    log.info(
        "Unique domains: %s → %s lists",
        v(len(sorted_domains)),
        v(len(chunks)),
    )

    sync_domain_lists(session, base, chunks, all_rules, all_lists)


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
