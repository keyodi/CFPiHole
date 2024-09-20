from typing import List
from logger_config import CustomFormatter
import cloudflare_api
import time

# Configure logging
logger = CustomFormatter.configure_logger("cloudflare_setup")


def get_block_lists(name_prefix: str):

    return cloudflare_api.get_lists(name_prefix)


def create_firewall_policy(
    name_prefix: str, list_ids: List[str] = None, regex_tld: str = None
):
    """Creates or updates a blocking policy in cloudflare_api."""

    # Get existing policies
    cf_policies = cloudflare_api.get_firewall_policies(name_prefix)
    num_policies = len(cf_policies)

    if "TLDs" in name_prefix:
        # Remove duplicates, sort, and create regex
        unique_tlds = sorted(set(tld.replace(".", "") for tld in list_ids or []))
        regex_tld = rf"[.](|{"|".join(unique_tlds)})$"
        list_ids = None

    if num_policies == 0:
        cloudflare_api.create_gateway_policy(
            name_prefix, list_ids=list_ids, regex_tld=regex_tld
        )
    elif num_policies == 1:
        cloudflare_api.delete_firewall_policy(name_prefix, cf_policies[0]["id"])
        cloudflare_api.create_gateway_policy(
            name_prefix, list_ids=list_ids, regex_tld=regex_tld
        )
    else:
        logger.error("One or more than one firewall policy found")
        raise Exception("More than one firewall policy found")

    return []


def delete_firewall_policy(name_prefix: str):
    """Deletes the blocking policy in cloudflare_api."""

    # Get existing policies
    cf_policies = cloudflare_api.get_firewall_policies(name_prefix)

    if cf_policies:
        cloudflare_api.delete_firewall_policy(name_prefix, cf_policies[0]["id"])
    else:
        logger.info(f"No firewall policy {name_prefix} found to delete")

    return []


def delete_lists_policy(name_prefix: str, cf_lists: List[str]):
    """Deletes the blocking policy and then the lists in cloudflare_api."""
    delete_firewall_policy(name_prefix)

    for l in cf_lists:
        cloudflare_api.delete_list(l["id"], l["name"])

        # Sleep to prevent rate limit
        time.sleep(1)

    return []


def create_lists_policy(name_prefix: str, unique_domains: List[str]):
    """Creates new lists with chunking and handles rate limits."""

    # Sleep to prevent rate limit
    logger.warning("Pausing for 60 seconds to prevent rate limit, please wait")
    time.sleep(60)

    logger.info("Creating lists, please wait")

    cf_lists = []
    # Chunk the domains into lists of 1000 and create them
    for chunk in chunk_list(unique_domains, 1000):
        list_name = f"{name_prefix} {len(cf_lists) + 1}"
        _list = cloudflare_api.create_list(list_name, chunk)
        cf_lists.append(_list)

        # Sleep to prevent rate limit
        time.sleep(1)

    create_firewall_policy(name_prefix, [l["id"] for l in cf_lists])

    return []


def chunk_list(_list: List[str], n: int):
    for i in range(0, len(_list), n):
        yield _list[i : i + n]

    return []
