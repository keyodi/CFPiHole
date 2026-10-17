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

DOMAIN_PREFIX = "[CFPihole] Block Ads"
TLD_PREFIX = "[CFPihole] Block TLDs"
MAX_LISTS, PER_LIST = 300, 1000  # Cloudflare Gateway limits
MAX_MB = 10
COMMENT_CHARS = frozenset("!#;/[")
HOSTS_IPS = frozenset(("127.0.0.1", "0.0.0.0"))

log = logging.getLogger("cfpihole")


def load_config() -> tuple[list[str], str | None]:
    """Read config.ini and return (block_list_urls, tld_list_url)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        read = parser.read("config.ini")
    except configparser.Error as error:
        sys.exit(f"Invalid config.ini: {error}")
    if not read:
        sys.exit("Config file not found: config.ini")

    def urls(section: str) -> list[str]:
        return list(parser[section].values()) if section in parser else []

    blocks, tlds = urls("BlockLists"), urls("TLDList")
    if not blocks and not tlds:
        sys.exit("config.ini has no [BlockLists] or [TLDList] entries")
    if len(tlds) > 1:
        sys.exit("Only one URL is supported in [TLDList]")
    for url in blocks + tlds:
        if not url.startswith("https://"):
            sys.exit(f"URL must use https://: {url}")
    return list(dict.fromkeys(blocks)), (tlds or [None])[0]


def download(url: str) -> bytes | None:
    """Download a URL (https only, size-capped); None on failure."""
    data = bytearray()
    try:
        with requests.get(url, timeout=15, stream=True) as response:
            response.raise_for_status()
            if not response.url.startswith("https://"):
                log.error("Refused non-HTTPS redirect for %s", v(url))
                return None
            for chunk in response.iter_content(65536):
                data += chunk
                if len(data) > MAX_MB << 20:
                    log.error(
                        "Refused response over %s MB for %s", v(MAX_MB), v(url)
                    )
                    return None
    except requests.RequestException as error:
        log.error("Failed downloading %s: %s", v(url), v(error))
        return None
    log.info("Downloaded: %s %s", v(url), v(f"{len(data) / 1024:.0f} KB"))
    return bytes(data)


def clean_lines(raw: bytes) -> list[str]:
    """Non-empty, non-comment, lower-cased lines."""
    text = raw.decode("utf-8", errors="ignore").lower()
    lines = map(str.strip, text.splitlines())
    return [line for line in lines if line and line[0] not in COMMENT_CHARS]


def parse_tlds(raw: bytes) -> set[str]:
    """Return the set of TLDs found in raw_bytes."""
    return {
        tld
        for line in clean_lines(raw)
        if (tld := "".join(c for c in line if c.isalnum() or c in "-.").strip("."))
    }


def parse_domains(raw: bytes) -> set[str]:
    words = [line.split() for line in clean_lines(raw)]
    # Hosts file if most of the first 30 lines start with a hosts IP.
    head = [w[0] for w in words[:30]]
    if sum(first in HOSTS_IPS for first in head) * 2 > len(head):
        return {
            w[1].rstrip(".")
            for w in words
            if len(w) > 1 and "localhost" not in w[1]
        }
    return {w[0].rstrip(".") for w in words}


def list_number(name: str) -> int:
    """Number at the end of '<DOMAIN_PREFIX> <n>' (odd names last)."""
    try:
        return int(name[len(DOMAIN_PREFIX):])
    except ValueError:
        return sys.maxsize


def sync_domain_lists(session, gateway, chunks, rules, lists) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one rule."""
    old = sorted(
        cf.with_prefix(lists, DOMAIN_PREFIX),
        key=lambda item: list_number(item["name"]),
    )
    if surplus := old[len(chunks):]:
        # A list used by a rule can't be deleted, so delete the rule first.
        cf.ensure_rule(session, gateway, rules, DOMAIN_PREFIX, None, False)
        rules = []
        cf.delete(session, gateway, "lists", surplus)

    if chunks:
        log.info("Updating lists, please wait")
    ids = [
        cf.save_list(
            session,
            gateway,
            f"{DOMAIN_PREFIX} {position}",
            chunk,
            old[position - 1]["id"] if position <= len(old) else None,
        )
        for position, chunk in enumerate(chunks, 1)
    ]
    traffic = cf.domain_traffic(ids) if ids else None
    cf.ensure_rule(session, gateway, rules, DOMAIN_PREFIX, traffic, False)


def main() -> None:
    load_dotenv()
    setup_logging()

    token = os.getenv("CF_API_TOKEN") or sys.exit("Missing CF_API_TOKEN")
    account = os.getenv("CF_IDENTIFIER") or sys.exit("Missing CF_IDENTIFIER")
    gateway = f"https://api.cloudflare.com/client/v4/accounts/{account}/gateway"
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"

    block_urls, tld_url = load_config()

    def fetch(url, parse):
        raw = download(url)
        return None if raw is None else parse(raw)

    # Download everything in parallel.
    with ThreadPoolExecutor() as pool:
        tld_job = pool.submit(fetch, tld_url, parse_tlds) if tld_url else None
        fetched = list(pool.map(lambda u: fetch(u, parse_domains), block_urls))

    failed = [url for url, found in zip(block_urls, fetched) if found is None]
    if failed:
        log.warning(
            "Skipping %s failed download(s): %s",
            v(len(failed)),
            v(", ".join(failed)),
        )
    domains = set().union(*(found for found in fetched if found is not None))

    tlds = tld_job.result() if tld_job else None
    if tld_url and tlds is None:
        log.warning("TLD list unavailable — no TLD-level blocking this run")
    tlds = tlds or set()
    suffixes = tuple("." + tld for tld in tlds)
    domains = sorted(d for d in domains if not d.endswith(suffixes))

    if failed and not domains:
        sys.exit("All block-list downloads failed — not modifying Cloudflare")

    rules = cf.get_all(session, gateway, "rules")
    lists = cf.get_all(session, gateway, "lists")

    tld_rule = cf.tld_traffic(sorted(tlds)) if tlds else None
    cf.ensure_rule(session, gateway, rules, TLD_PREFIX, tld_rule, True)

    chunks = [domains[i:i + PER_LIST] for i in range(0, len(domains), PER_LIST)]
    # Lists that aren't ours still count towards Cloudflare's limit.
    others = len(lists) - len(cf.with_prefix(lists, DOMAIN_PREFIX))
    if len(chunks) + others > MAX_LISTS:
        sys.exit(f"Would exceed {MAX_LISTS} list limit — use smaller block lists")

    if domains:
        log.info("Unique domains: %s → %s lists", v(len(domains)), v(len(chunks)))
    else:
        log.warning("No domains to block — removing existing lists/rule")
    sync_domain_lists(session, gateway, chunks, rules, lists)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except cf.CloudflareAPIError as error:
        log.critical("Cloudflare API error: %s", error)
        sys.exit(64)
    except Exception as error:
        log.critical("Fatal error: %s", error, exc_info=True)
        sys.exit(1)
