import configparser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import cloudflare_config
import requests
from logger_config import CustomFormatter

# Constants
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
FILE_PATH_CONFIG = "config.ini"
TMP_DIR = Path("./tmp")
TIMEOUT = 15
MAX_LISTS_ALLOWED = 300
LIST_CHUNK_SIZE = 1000

logger = CustomFormatter.configure_logger("main")


def download_file(session: requests.Session, url: str, name: str) -> None:
    """Download a URL and save it to TMP_DIR/<name>."""
    try:
        response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        response.raise_for_status()
        (TMP_DIR / name).write_bytes(response.content)
        logger.info(f"Downloaded {url} ({len(response.content) / 1024:.0f} KB)")
    except requests.RequestException as e:
        logger.error(f"Error downloading {url}: {e}")


def parse_lines(path: Path) -> list[str]:
    """Read non-comment, non-empty lines from a file."""
    if not path.exists():
        logger.warning(f"Missing {path}, skipping")
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return [
            stripped
            for line in f
            if (stripped := line.strip())
            and not stripped.startswith(("!", "#", ";", "//", "["))
        ]


def parse_tld_file(name: str) -> set[str]:
    """Parse Adblock-formatted TLDs; returns bare TLD strings."""
    tlds = {
        stripped
        for line in parse_lines(TMP_DIR / name)
        if (stripped := line.removeprefix("||").removesuffix("^"))
    }
    logger.info(f"TLDs loaded: {CustomFormatter.GREEN}{len(tlds)}")
    return tlds


def is_tld_blocked(domain: str, tld_set: set[str]) -> bool:
    """Return True if the domain falls under a blocked TLD."""
    parts = domain.rsplit(".", 2)
    return (len(parts) >= 2 and parts[-1] in tld_set) or (
        len(parts) == 3 and f"{parts[-2]}.{parts[-1]}" in tld_set
    )


def parse_domain_file(name: str, tld_set: set[str]) -> set[str]:
    """Convert a hosts or adblock list to a set of domains."""
    lines = parse_lines(TMP_DIR / name)
    if not lines:
        return set()

    is_hosts = lines[0].startswith(("127.0.0.1 ", "0.0.0.0 "))
    domains: set[str] = set()

    for line in lines:
        parts = line.split()
        if not parts:
            continue
        domain = (
            (parts[1] if is_hosts and len(parts) > 1 else parts[0]).lower().rstrip(".")
        )
        if is_hosts and "localhost" in domain:
            continue
        if tld_set and is_tld_blocked(domain, tld_set):
            continue
        domains.add(domain)

    logger.debug(f"{name} — domains: {CustomFormatter.YELLOW}{len(domains)}")
    return domains


def run() -> None:
    TMP_DIR.mkdir(exist_ok=True)

    config = configparser.ConfigParser()
    config.read(FILE_PATH_CONFIG)

    if not config.has_section("Lists"):
        logger.error(
            f"{FILE_PATH_CONFIG} is missing [Lists], doesn't exist, or has duplicate values."
        )
        return

    list_names = config.options("Lists")
    tld_files = [n for n in list_names if "tld" in n.lower()]
    block_files = [n for n in list_names if "tld" not in n.lower()]

    cf_lists, total_cf_lists = cloudflare_config.get_block_lists(NAME_PREFIX)
    diff_cf_lists = len(total_cf_lists) - len(cf_lists)
    logger.debug(
        f"CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
    )
    logger.debug(
        f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{diff_cf_lists}"
    )

    logger.info("Starting concurrent downloads...")
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=min(len(list_names), 20)) as ex:
            futures = [
                ex.submit(download_file, session, config["Lists"][n], n)
                for n in list_names
            ]
            for f in futures:
                f.result()

    tld_set = parse_tld_file(tld_files[0]) if tld_files else set()

    with ThreadPoolExecutor(max_workers=min(len(block_files), 8)) as ex:
        all_domains: set[str] = set().union(
            *ex.map(lambda n: parse_domain_file(n, tld_set), block_files)
        )

    unique_domains = len(all_domains)
    total_new_lists = -(-unique_domains // LIST_CHUNK_SIZE)

    logger.info(f"Unique domains: {CustomFormatter.GREEN}{unique_domains}")
    logger.info(f"Lists to create: {CustomFormatter.GREEN}{total_new_lists}")

    if unique_domains == sum(l["count"] for l in cf_lists):
        logger.warning("Lists are the same size, stopping")
        return

    if (total_new_lists + diff_cf_lists) > MAX_LISTS_ALLOWED:
        logger.warning(
            f"Max {MAX_LISTS_ALLOWED} lists allowed. Select smaller blocklists, stopping"
        )
        return

    cloudflare_config.delete_firewall_policy(NAME_PREFIX_TLD)
    if tld_set:
        cloudflare_config.create_firewall_policy(NAME_PREFIX_TLD, sorted(tld_set))

    cloudflare_config.delete_lists_policy(NAME_PREFIX, cf_lists)
    cloudflare_config.create_lists_policy(NAME_PREFIX, sorted(all_domains))

    logger.info(f"{CustomFormatter.GREEN}Done")


if __name__ == "__main__":
    run()
