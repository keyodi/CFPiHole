from __future__ import annotations

from typing import Any
import os

import requests
from requests.adapters import HTTPAdapter
from dotenv import load_dotenv

from logger_config import CustomFormatter

# Load environment variables
load_dotenv()

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_IDENTIFIER = os.getenv("CF_IDENTIFIER")

# Credentials check
if not CF_API_TOKEN:
    raise ValueError("Missing CF_API_TOKEN environment variable")
if not CF_IDENTIFIER:
    raise ValueError("Missing CF_IDENTIFIER environment variable")

BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway"

# Configure logging
logger = CustomFormatter.configure_logger("cloudflare")

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {CF_API_TOKEN}"})
session.mount("https://", HTTPAdapter(pool_maxsize=20, pool_connections=20))


def api_call(method: Any, endpoint: str, json: dict | None = None) -> Any:
    """Make a Cloudflare Gateway API call and return the parsed result. """
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = method(url, json=json)
        response.raise_for_status()
        logger.debug("[%s] %s", endpoint, response.status_code)
        return response.json().get("result", [])
    except Exception as exc:
        logger.error(
            "HTTP error occurred. This may be caused by Cloudflare rate limiting: %s",
            exc,
        )
        raise SystemExit(64)


def get_items_by_name(endpoint: str, name_prefix: str) -> tuple[list[dict], list[dict]]:
    """Retrieve items from an endpoint and return (filtered, all_items)."""
    data = api_call(session.get, endpoint) or []
    filtered = [item for item in data if item.get("name", "").startswith(name_prefix)]
    return filtered, data


def get_lists(name_prefix: str) -> tuple[list[dict], list[dict]]:
    """Retrieve lists matching the given name prefix."""
    return get_items_by_name("lists", name_prefix)


def get_policies(name_prefix: str) -> list[dict]:
    """Retrieve gateway policies (rules) matching the given name prefix."""
    policies, _ = get_items_by_name("rules", name_prefix)
    return policies


def create_list(name: str, domains: list[str]) -> dict:
    """Create a named list populated with domains."""
    payload = {
        "name": name,
        "description": "Created by script.",
        "type": "DOMAIN",
        "items": [{"value": domain} for domain in domains],
    }
    result = api_call(session.post, "lists", json=payload)
    logger.debug("Created list %s", name)
    return result


def delete_list(list_id: str, name: str) -> None:
    """Delete a list given its ID."""
    api_call(session.delete, f"lists/{list_id}")
    logger.debug("Deleted list %s", name)


def delete_policy(name_prefix: str) -> None:
    """Delete a firewall policy matching the given name prefix. """
    policies = get_policies(name_prefix)

    if not policies:
        logger.info("No firewall policy %s found to delete", name_prefix)
        return
    if len(policies) > 1:
        raise ValueError("More than one firewall policy found")

    api_call(session.delete, f"rules/{policies[0]['id']}")
    logger.info("Deleted policy %s", name_prefix)


def create_policy(name: str, list_ids: list[str] | None = None, regex_tld: str | None = None) -> None:
    """Create a gateway policy that blocks based on list IDs or a TLD regex."""
    if list_ids:
        traffic = " or ".join([f"any(dns.domains[*] in ${list_id})" for list_id in list_ids])
        block_page_enabled = False
    else:
        traffic = f'any(dns.domains[*] matches "{regex_tld}")'
        block_page_enabled = True

    payload = {
        "name": name,
        "description": "Created by script.",
        "action": "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": traffic,
        "rule_settings": {"block_page_enabled": block_page_enabled},
    }
    api_call(session.post, "rules", json=payload)
    logger.info("Created firewall policy: %s", name)


def create_policy_with_tlds(name: str, tld_list: list[str]) -> None:
    """Create a TLD-based blocking policy from a list of TLDs."""
    regex_tld = rf"[.](|{'|'.join(tld_list)})$"
    create_policy(name, regex_tld=regex_tld)


def create_lists_and_policy(name_prefix: str, unique_domains: list[str], chunk_size: int) -> None:
    """Chunk the domains into lists, create them in Cloudflare, then add a policy referencing the lists."""
    logger.info("%sCreating lists, please wait", CustomFormatter.YELLOW)
    list_ids: list[str] = []

    for i, chunk in enumerate(chunk_list(unique_domains, chunk_size), 1):
        list_name = f"{name_prefix} {i}"
        created_list = create_list(list_name, chunk)
        list_ids.append(created_list["id"])

    create_policy(name_prefix, list_ids=list_ids)


def delete_lists_and_policy(name_prefix: str, lists: list[dict]) -> None:
    """Delete the firewall policy and the provided lists."""
    delete_policy(name_prefix)
    logger.info("%sDeleting lists, please wait", CustomFormatter.YELLOW)
    for list_item in lists:
        delete_list(list_item["id"], list_item["name"])


def chunk_list(items: list[str], chunk_size: int):
    """Yield successive chunks of size chunk_size from items."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]
