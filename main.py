import configparser
import cloudflare_api
import requests
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from logger_config import CustomFormatter
from pathlib import Path

# Constants
NAME_PREFIX     = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE     = "config.ini"
TMP_DIR         = Path("./tmp")
TIMEOUT         = 15
MAX_LISTS       = 300
CHUNK_SIZE      = 1000
COMMENT_CHARS   = frozenset("!#;/[")

logger = CustomFormatter.configure_logger("main")


def download_file(session: requests.Session, url: str, name: str) -> None:
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        (TMP_DIR / name).write_bytes(response.content)
        logger.info(f"Downloaded {url} ({len(response.content) / 1024:.0f} KB)")
    except requests.RequestException as e:
        logger.error(f"Error downloading {url}: {e}")


def read_lines(path: Path) -> list[str]:
    """Return non-empty, non-comment lines from a file."""
    if not path.exists():
        logger.warning(f"Missing {path}, skipping")
        return []

    raw = path.read_bytes().decode("utf-8", errors="ignore")
    return [
        s
        for line in raw.splitlines()
        if (s := line.strip()) and s[0] not in COMMENT_CHARS
    ]


def parse_tld_file(name: str) -> set[str]:
    """Strip adblock syntax (||tld^) and return bare TLD strings."""
    tlds = {
        line.removeprefix("||").removesuffix("^") for line in read_lines(TMP_DIR / name)
    }
    logger.info(f"TLDs loaded: {CustomFormatter.GREEN}{len(tlds)}")
    return tlds


def is_tld_blocked(domain: str, tld_set: set[str]) -> bool:
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2:
        if parts[-1] in tld_set:
            return True
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in tld_set:
            return True
    return False


def parse_domain_file(name: str, tld_set: set[str]) -> set[str]:
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
    TMP_DIR.mkdir(exist_ok=True)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not validate_config(config):
        return

    list_names = config.options("Lists")
    tld_files = [n for n in list_names if "tld" in n.lower()]
    block_files = [n for n in list_names if "tld" not in n.lower()]

    cf_lists, total_cf_lists = cloudflare_api.get_lists(NAME_PREFIX)
    extra_lists = len(total_cf_lists) - len(cf_lists)
    logger.debug(
        f"CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
    )
    logger.debug(
        f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{extra_lists}"
    )

    logger.info("Starting concurrent downloads...")

    MAX_DOWNLOAD_WORKERS = min(len(list_names), 32)
    MAX_PARSE_WORKERS = min(len(block_files), 16)

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=MAX_DOWNLOAD_WORKERS) as ex:
            futures = [
                ex.submit(download_file, session, config["Lists"][n], n)
                for n in list_names
            ]
            for future in futures:
                future.result()

    # Parse TLDs if available
    tld_set = parse_tld_file(tld_files[0]) if tld_files else set()

    # Parse all block files concurrently and stream results
    all_domains: set[str] = set()
    with ThreadPoolExecutor(max_workers=MAX_PARSE_WORKERS) as ex:
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

    cloudflare_api.delete_lists_and_policy(NAME_PREFIX, cf_lists)
    if tld_set:
        cloudflare_api.create_firewall_policy_with_domains(NAME_PREFIX_TLD, tld_list=sorted(tld_set))

    cloudflare_api.create_lists_and_policy(NAME_PREFIX, sorted(all_domains))

    logger.info(f"{CustomFormatter.GREEN}Done")


if __name__ == "__main__":
    run()
