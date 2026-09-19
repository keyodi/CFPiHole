import configparser
import logging
import os
import sys

import requests

import cloudflare_api as cf
from cloudflare_api import CloudflareAPIError

# constants

NAME_PREFIX     = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CHUNK_SIZE      = 1000   # Cloudflare list size limit
MAX_LISTS       = 300    # Cloudflare account list limit
COMMENT_CHARS   = set("!#;/[")

# ── colored logging ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
COLORS = {
    logging.DEBUG:    "\033[36m",   # cyan
    logging.INFO:     "\033[32m",   # green
    logging.WARNING:  "\033[33m",   # yellow
    logging.ERROR:    "\033[31m",   # red
    logging.CRITICAL: "\033[1;31m", # bold red
}

class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLORS.get(record.levelno, RESET)
        record.levelname = f"{color}{record.levelname}{RESET}"
        record.msg = f"{color}{record.msg}{RESET}"
        return super().format(record)

handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter("%(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler])
log = logging.getLogger("cfpihole")

# ── config loading ─────────────────────────────────────────────────────────────

def load_config(path="config.ini"):
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")
    p = configparser.ConfigParser(interpolation=None)
    p.read(path)
    block_urls = dict(p.items("BlockLists")) if p.has_section("BlockLists") else {}
    tld_urls   = dict(p.items("TLDList"))   if p.has_section("TLDList")   else {}
    if not block_urls and not tld_urls:
        sys.exit("config.ini has no [BlockLists] or [TLDList] entries")
    for url in list(block_urls.values()) + list(tld_urls.values()):
        if not url.startswith("https://"):
            sys.exit(f"URL must use https://: {url}")
    if len(tld_urls) > 1:
        sys.exit("Only one URL is supported in [TLDList]")
    return block_urls, next(iter(tld_urls.values()), None)

# ── downloading ────────────────────────────────────────────────────────────────

def download(url):
    """Download a URL and return raw bytes, or None on failure."""
    try:
        r = requests.get(url, timeout=15, allow_redirects=True)
        r.raise_for_status()
        log.info("Downloaded %s (%.0f KB)", url, len(r.content) / 1024)
        return r.content
    except requests.RequestException as exc:
        log.error("Failed downloading %s: %s", url, exc)
        return None

# ── parsing ────────────────────────────────────────────────────────────────────

def _clean_lines(raw):
    """Return non-empty, non-comment lines from raw bytes."""
    text = raw.decode("utf-8", errors="ignore")
    return [s for line in text.splitlines()
            if (s := line.strip()) and s[0] not in COMMENT_CHARS]

def parse_tlds(raw):
    tlds = set()
    for line in _clean_lines(raw):
        cleaned = "".join(ch for ch in line if ch.isalnum() or ch in "-.").strip(".")
        if cleaned:
            tlds.add(cleaned)
    return tlds

def _tld_blocked(domain, tld_set):
    parts = domain.rsplit(".", 2)
    return (len(parts) >= 2 and parts[-1] in tld_set) or \
           (len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in tld_set)

def parse_domains(raw, tld_set):
    lines = _clean_lines(raw)
    if not lines:
        return set()
    sample = lines[:30]
    is_hosts = sum(1 for l in sample if l.startswith(("127.0.0.1 ", "0.0.0.0 "))) > len(sample) / 2

    domains = set()
    for line in lines:
        parts = line.split()
        domain = (parts[1] if is_hosts and len(parts) > 1 else parts[0]).lower().rstrip(".")
        if is_hosts and "localhost" in domain:
            continue
        if tld_set and _tld_blocked(domain, tld_set):
            continue
        domains.add(domain)
    return domains

# ── main ───────────────────────────────────────────────────────────────────────

def main():
    CF_API_TOKEN      = os.getenv("CF_API_TOKEN")  or sys.exit("Missing CF_API_TOKEN")
    CF_IDENTIFIER = os.getenv("CF_IDENTIFIER") or sys.exit("Missing CF_IDENTIFIER")
    base = f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway"

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {CF_API_TOKEN}"

    block_urls, tld_url = load_config()

    # Download and parse TLD list
    tld_set = set()
    if tld_url:
        raw = download(tld_url)
        if raw:
            tld_set = parse_tlds(raw)

    # Download and parse block lists
    all_domains = set()
    any_failed = False
    for name, url in block_urls.items():
        raw = download(url)
        if raw is None:
            any_failed = True
        else:
            all_domains.update(parse_domains(raw, tld_set))

    if block_urls and any_failed and not all_domains:
        sys.exit("All block-list downloads failed — not modifying Cloudflare")

    # Sync TLD rule
    cf.delete_rule(session, base, NAME_PREFIX_TLD)
    if tld_set:
        cf.create_tld_rule(session, base, NAME_PREFIX_TLD, sorted(tld_set))

    # Sync domain lists + rule
    existing_lists = [l for l in cf.get_lists(session, base) if l["name"].startswith(NAME_PREFIX)]
    existing_total = sum(l.get("count", 0) for l in existing_lists)

    if not all_domains:
        log.warning("No domains to block — removing existing lists/rule")
        cf.delete_rule(session, base, NAME_PREFIX)
        cf.delete_lists_by_prefix(session, base, NAME_PREFIX)
        return

    if len(all_domains) == existing_total:
        log.info("Domain count unchanged (%d) — nothing to do", existing_total)
        return

    chunks = [sorted(all_domains)[i:i + CHUNK_SIZE]
              for i in range(0, len(all_domains), CHUNK_SIZE)]

    all_lists = cf.get_lists(session, base)
    extra_lists = len(all_lists) - len(existing_lists)
    if len(chunks) + extra_lists > MAX_LISTS:
        sys.exit(f"Would exceed {MAX_LISTS} list limit — use smaller block lists")

    log.info("Unique domains: %d  →  %d lists", len(all_domains), len(chunks))

    cf.delete_rule(session, base, NAME_PREFIX)
    cf.delete_lists_by_prefix(session, base, NAME_PREFIX)

    list_ids = [cf.create_list(session, base, f"{NAME_PREFIX} {i}", chunk)
                for i, chunk in enumerate(chunks, 1)]

    cf.create_domain_rule(session, base, NAME_PREFIX, list_ids)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except CloudflareAPIError as exc:
        log.critical("Cloudflare API error: %s", exc)
        sys.exit(64)  # signals GitHub Actions to retry
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
