from typing import List
from logger_config import CustomFormatter
from dotenv import load_dotenv
import requests
import os


# Load environment variables
load_dotenv()

# Credentials check (moved outside session creation)
CF_API_TOKEN = os.getenv("CF_API_TOKEN") or os.environ.get("CF_API_TOKEN")
CF_IDENTIFIER = os.getenv("CF_IDENTIFIER") or os.environ.get("CF_IDENTIFIER")
if not CF_API_TOKEN or not CF_IDENTIFIER:
    raise Exception("Missing Cloudflare credentials")

# Configure logging
logger = CustomFormatter.configure_logger("cloudflare")

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {CF_API_TOKEN}"})


def api_call(method, endpoint, json=None):
    """
    Makes an API call with error handling and logging.
    """
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/{endpoint}"
    response = method(url, json=json)
    response.raise_for_status()

    logger.debug(f"[{endpoint}] {response.status_code}")

    return response.json()["result"] if response.json() else []


def get_lists(name_prefix: str):
    """
    Retrieves lists with a specific name prefix.
    """
    data = api_call(session.get, "lists")

    return [l for l in data if l["name"].startswith(name_prefix)], data


def create_list(name: str, domains: List[str]):
    """
    Creates a new list with the specified name and domains.
    """
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
    logger.info(f"Created list {name}")

    return data


def delete_list(list_id: str, name: str):
    """
    Deletes a list by its ID.
    """
    api_call(session.delete, f"lists/{list_id}")
    logger.info(f"Deleted list {name}")


def get_firewall_policies(name_prefix: str):
    """
    Retrieves firewall policies with a specific name prefix.
    """
    data = api_call(session.get, "rules")

    return [l for l in data if l["name"].startswith(name_prefix)]


def delete_firewall_policy(policy_id: str):
    """
    Deletes a firewall policy by its ID.
    """
    api_call(session.delete, f"rules/{policy_id}")
    logger.debug(f"Deleted policy {policy_id}")


def _create_gateway_policy(
    method,
    name: str,
    policy_id: str = None,
    list_ids: List[str] = None,
    regex_tld: str = None,
):
    """
    Creates a gateway policy with blocking logic based on list IDs.
    """
    traffic = (
        "or".join([f"any(dns.domains[*] in ${l})" for l in list_ids])
        if list_ids
        else f'not(any(dns.domains[*] matches "{regex_tld}"))'
    )
    endpoint = f"rules/{policy_id}" if policy_id else "rules"
    block_page = bool(regex_tld)
    data = api_call(
        method,
        endpoint,
        json={
            "name": name,
            "description": "Created by script.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": block_page},
        },
    )

    return data


def create_gateway_policy(name: str, list_ids: List[str]):
    """
    Creates a gateway policy blocking domains in the specified lists.
    """
    return _create_gateway_policy(session.post, name, list_ids=list_ids)


def update_gateway_policy(name: str, policy_id: str, list_ids: List[str]):
    """
    Updates a gateway policy with new blocking logic based on list IDs.
    """
    return _create_gateway_policy(session.put, name, policy_id=policy_id, list_ids=list_ids)


def create_gateway_policy_tld(name: str, regex_tld: str):
    """
    Creates a gateway policy blocking domains in the specified lists.
    """
    return _create_gateway_policy(session.post, name, regex_tld=regex_tld)


def update_gateway_policy_tld(name: str, policy_id: str, regex_tld: str):
    """
    Updates a gateway policy with new blocking logic based on list IDs.
    """
    return _create_gateway_policy(session.put, name, policy_id=policy_id, regex_tld=regex_tld)
