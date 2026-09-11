from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

import sources
from cloudflare_api import CFList, CloudflareGateway
from config import load_config
from logger_config import CustomFormatter

load_dotenv()

NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
CONFIG_FILE = "config.ini"

# Cloudflare Gateway API limits
MAX_LISTS = 300
CHUNK_SIZE = 1000

logger = CustomFormatter.configure_logger("main")


def chunk_list(items: list[str], chunk_size: int):
    """Yield successive chunks of size chunk_size from items."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def sync_tld_policy(gateway: CloudflareGateway, tld_set: set[str]) -> None:
    """TLD policy is independent of the domain-list policy: rebuild from tld_set alone."""
    gateway.delete_policy(NAME_PREFIX_TLD)
    if tld_set:
        gateway.create_tld_policy(NAME_PREFIX_TLD, sorted(tld_set))
        logger.info("TLD policy created: %s%s TLDs", CustomFormatter.GREEN, len(tld_set))
    else:
        logger.info("No TLDs to block, TLD policy removed")


def sync_domain_policy(
    gateway: CloudflareGateway,
    domains: set[str],
    existing_lists: list[CFList],
    extra_lists: int,
) -> None:
    """Domain-list policy is independent of the TLD policy."""
    if not domains:
        logger.warning("No domains to block, removing existing lists/policy")
        gateway.delete_policy(NAME_PREFIX)
        for lst in existing_lists:
            gateway.delete_list(lst)
        return

    existing_total = sum(lst.count for lst in existing_lists)
    if len(domains) == existing_total:
        logger.warning("Domain count unchanged (%s), stopping", existing_total)
        return

    new_list_count = (len(domains) - 1) // CHUNK_SIZE + 1
    if new_list_count + extra_lists > MAX_LISTS:
        logger.warning("Max %s lists allowed. Select smaller blocklists, stopping", MAX_LISTS)
        return

    logger.info("Unique domains: %s%s", CustomFormatter.GREEN, len(domains))
    logger.info("Lists to create: %s%s", CustomFormatter.GREEN, new_list_count)

    gateway.delete_policy(NAME_PREFIX)
    for lst in existing_lists:
        gateway.delete_list(lst)

    logger.info("%sCreating lists, please wait", CustomFormatter.YELLOW)
    list_ids = [
        gateway.create_list(f"{NAME_PREFIX} {i}", batch).id
        for i, batch in enumerate(chunk_list(sorted(domains), CHUNK_SIZE), 1)
    ]
    gateway.create_domain_policy(NAME_PREFIX, list_ids)


def run() -> None:
    cf_token = os.getenv("CF_API_TOKEN")
    cf_account = os.getenv("CF_IDENTIFIER")
    if not cf_token:
        raise SystemExit("Missing CF_API_TOKEN environment variable")
    if not cf_account:
        raise SystemExit("Missing CF_IDENTIFIER environment variable")

    config = load_config(CONFIG_FILE)
    gateway = CloudflareGateway(account_id=cf_account, api_token=cf_token)

    # Fetch the TLD source alongside the block-list sources in one batch of downloads.
    fetch_urls = dict(config.block_list_urls)
    if config.tld_list_url:
        fetch_urls["__tld__"] = config.tld_list_url

    logger.info("Starting concurrent downloads...")
    fetched = sources.fetch_all(fetch_urls)

    tld_set: set[str] = set()
    if config.tld_list_url:
        tld_raw = fetched.content.get("__tld__")
        if tld_raw is not None:
            tld_set = sources.parse_tlds(tld_raw)

    all_domains: set[str] = set()
    for name in config.block_list_urls:
        raw = fetched.content.get(name)
        if raw is not None:
            all_domains.update(sources.parse_domains(raw, tld_set))

    domain_failures = [n for n in config.block_list_urls if n in fetched.failed]
    if config.block_list_urls and domain_failures and not all_domains:
        raise SystemExit(
            f"All domain-list downloads failed ({', '.join(domain_failures)}), "
            "refusing to modify existing lists"
        )

    existing_lists = gateway.lists(NAME_PREFIX)
    extra_lists = len(gateway.all_lists()) - len(existing_lists)
    logger.debug("CFPiHole lists in Cloudflare: %s%s", CustomFormatter.YELLOW, len(existing_lists))
    logger.debug("Additional lists in Cloudflare: %s%s", CustomFormatter.YELLOW, extra_lists)

    sync_tld_policy(gateway, tld_set)
    sync_domain_policy(gateway, all_domains, existing_lists, extra_lists)


if __name__ == "__main__":
    try:
        run()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception:
        logger.critical("Fatal error", exc_info=True)
        sys.exit(1)
