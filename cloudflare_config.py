from logger_config import CustomFormatter
import cloudflare_api
# Optional: import time

# Configure logging
logger = CustomFormatter.configure_logger("cloudflare_setup")

def get_block_lists(name_prefix: str):
    """Gets block lists with defined name prefix"""
    
    return cloudflare_api.get_lists(name_prefix)

def get_gateway_policies(name_prefix: str):
    """Gets block policies with defined name prefix"""

    cf_policies = cloudflare_api.get_firewall_policies(name_prefix)
    return cf_policies, len(cf_policies)

def create_firewall_policy(
    name_prefix: str,
    list_ids: list[str] | None = None,
    regex_tld: str | None = None,
):
    """Creates a block policy in the Firewall policy"""

    cf_policies, num_policies = get_gateway_policies(name_prefix)

    if "TLDs" in name_prefix:
        regex_tld = rf"[.](|{'|'.join(list_ids or [])})$"
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
        raise Exception("More than one firewall policy found")

def delete_firewall_policy(name_prefix: str):
    """Deletes a blocking policy from Cloudflare."""

    cf_policies, num_policies = get_gateway_policies(name_prefix)

    if num_policies == 0:
        logger.info(f"No firewall policy {name_prefix} found to delete")
        return
    elif num_policies != 1:
        raise Exception("More than one firewall policy found")

    cloudflare_api.delete_firewall_policy(name_prefix, cf_policies[0]["id"])

def delete_lists_policy(name_prefix: str, cf_lists: list[dict]):
    """Deletes the blocking policy and then the lists in cloudflare_api."""

    delete_firewall_policy(name_prefix)
    logger.info(f"{CustomFormatter.YELLOW} Deleting lists, please wait")
    for l in cf_lists:
        cloudflare_api.delete_list(l["id"], l["name"])
        # Optional: time.sleep(1.5)  # Prevent rate limit if needed

def create_lists_policy(name_prefix: str, unique_domains: list[str]):
    """Creates new lists with chunking and handles rate limits."""

    logger.info(f"{CustomFormatter.YELLOW} Creating lists, please wait")
    cf_lists = []
    for i, chunk in enumerate(chunk_list(unique_domains, 1000), 1):
        list_name = f"{name_prefix} {i}"
        _list = cloudflare_api.create_list(list_name, chunk)
        cf_lists.append(_list)
        # Optional: time.sleep(1.5)  # Prevent rate limit if needed

    create_firewall_policy(name_prefix, [l["id"] for l in cf_lists])

def chunk_list(_list: list[str], n: int):
    """Yield successive n-sized chunks from _list."""

    for i in range(0, len(_list), n):
        yield _list[i : i + n]

