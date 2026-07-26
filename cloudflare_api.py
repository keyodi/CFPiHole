from logger_config import CustomFormatter
from dotenv import load_dotenv
import requests
import os
import re

# Load environment variables
load_dotenv()

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_IDENTIFIER = os.getenv("CF_IDENTIFIER")
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway"

# Credentials check (moved outside session creation)
if not all([CF_API_TOKEN, CF_IDENTIFIER]):
    raise Exception("Missing Cloudflare credentials")

# Configure logging
logger = CustomFormatter.configure_logger("cloudflare")

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {CF_API_TOKEN}"})


def api_call(method, endpoint, json=None):
    """Makes an API call with error handling and logging."""
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = method(url, json=json)
        response.raise_for_status()
        logger.debug(f"[{endpoint}] {response.status_code}")
        return response.json().get("result", [])
    except Exception:
        logger.error(
            "HTTP error occurred - Error most likely caused by CF rate limit. Retrying"
        )
        raise SystemExit(64)


def get_lists(name_prefix: str):
    """Retrieves lists with a specific name prefix."""
    data = api_call(session.get, "lists") or []
    filtered = [l for l in data if l["name"].startswith(name_prefix)]
    return filtered, data


def create_list(name: str, domains: list[str]):
    """Creates a new list with the specified name and domains."""
    data = api_call(
        session.post,
        "lists",
        json={
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": [{"value": d} for d in domains],
        },
    )
    logger.debug(f"Created list {name}")
    return data


def delete_list(list_id: str, name: str):
    """Deletes a list by its ID."""
    api_call(session.delete, f"lists/{list_id}")
    logger.debug(f"Deleted list {name}")


def get_firewall_policies(name_prefix: str):
    """Retrieves firewall policies with a specific name prefix."""
    data = api_call(session.get, "rules") or []
    return [l for l in data if l["name"].startswith(name_prefix)]


def delete_firewall_policy_by_prefix(name_prefix: str):
    """Deletes a firewall policy by name prefix."""
    cf_policies = get_firewall_policies(name_prefix)

    if not cf_policies:
        logger.info(f"No firewall policy {name_prefix} found to delete")
        return
    elif len(cf_policies) > 1:
        raise Exception("More than one firewall policy found")

    api_call(session.delete, f"rules/{cf_policies[0]['id']}")
    logger.info(f"Deleted policy {name_prefix}")


def create_gateway_policy(
    name: str,
    list_ids: list[str] = None,
    regex_tld: str = None,
):
    """Creates a gateway policy with blocking logic based on list IDs or TLD regex."""
    traffic = " or ".join([f"any(dns.domains[*] in ${l})" for l in list_ids]) if list_ids else f'any(dns.domains[*] matches "{regex_tld}")'

    api_call(
        session.post,
        "rules",
        json={
            "name": name,
            "description": "Created by script.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": bool(regex_tld)},
        },
    )
    logger.info(f"Created firewall policy: {name}")


def create_firewall_policy_with_domains(
    name_prefix: str,
    list_ids: list[str] | None = None,
    tld_list: list[str] | None = None,
):
    """Creates a block policy in the Firewall policy.Handles TLD-based blocking by converting the TLD list into a regex pattern."""
    if "TLDs" in name_prefix:
        regex_tld = rf"[.](|{'|'.join(tld_list or [])})$"
        list_ids = None
    else:
        regex_tld = None

    create_gateway_policy(name_prefix, list_ids=list_ids, regex_tld=regex_tld)

def create_firewall_policy_with_domains(
    name_prefix: str,
    list_ids: list[str] | None = None,
    tld_list: list[str] | None = None,
):
     """Creates a block policy in the Firewall policy.Handles TLD-based blocking by converting the TLD list into a regex pattern."""
    if "TLDs" in name_prefix and tld_list:
        # More efficient: no empty branch, proper escaping
        escaped_tlds = "|".join(re.escape(tld) for tld in sorted(tld_list))
        regex_tld = rf"\.({escaped_tlds})$"
        list_ids = None
    else:
        regex_tld = None

    create_gateway_policy(name_prefix, list_ids=list_ids, regex_tld=regex_tld)

def delete_lists_and_policy(name_prefix: str, cf_lists: list[dict]):
    """Deletes the blocking policy and then the lists in Cloudflare."""
    delete_firewall_policy_by_prefix(name_prefix)
    logger.info(f"{CustomFormatter.YELLOW}Deleting lists, please wait")
    for l in cf_lists:
        delete_list(l["id"], l["name"])


def create_lists_and_policy(name_prefix: str, unique_domains: list[str], chunk_size: int = 1000):
    """Creates new lists with chunking and creates firewall policy."""
    logger.info(f"{CustomFormatter.YELLOW}Creating lists, please wait")
    list_ids = []

    for i, chunk in enumerate(chunk_list(unique_domains, chunk_size), 1):
        list_name = f"{name_prefix} {i}"
        _list = create_list(list_name, chunk)
        list_ids.append(_list["id"])

    create_firewall_policy_with_domains(name_prefix, list_ids=list_ids)


def chunk_list(_list: list[str], chunk_size: int):
    """Yield successive chunk_size-sized chunks from _list."""
    for i in range(0, len(_list), chunk_size):
        yield _list[i : i + chunk_size]
