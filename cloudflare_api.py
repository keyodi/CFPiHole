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

# Credentials check
if not all([CF_API_TOKEN, CF_IDENTIFIER]):
    raise ValueError("Missing Cloudflare credentials")

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


def get_items_by_name(endpoint: str, name_prefix: str) -> tuple[list, list]:
    """Generic helper: retrieves items from endpoint, returns (filtered, all)."""
    data = api_call(session.get, endpoint) or []
    filtered = [item for item in data if item["name"].startswith(name_prefix)]
    return filtered, data


def get_lists(name_prefix: str) -> tuple[list, list]:
    """Retrieves lists with a specific name prefix."""
    return get_items_by_name("lists", name_prefix)


def get_policies(name_prefix: str) -> list:
    """Retrieves firewall policies with a specific name prefix."""
    policies, _ = get_items_by_name("rules", name_prefix)
    return policies


def create_list(name: str, domains: list[str]) -> dict:
    """Creates a new list with the specified name and domains."""
    data = api_call(
        session.post,
        "lists",
        json={
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": [{"value": domain} for domain in domains],
        },
    )
    logger.debug(f"Created list {name}")
    return data


def delete_list(list_id: str, name: str) -> None:
    """Deletes a list by its ID."""
    api_call(session.delete, f"lists/{list_id}")
    logger.debug(f"Deleted list {name}")


def delete_policy(name_prefix: str) -> None:
    """Deletes a firewall policy by name prefix."""
    policies = get_policies(name_prefix)

    if not policies:
        logger.info(f"No firewall policy {name_prefix} found to delete")
        return
    elif len(policies) > 1:
        raise ValueError("More than one firewall policy found")

    api_call(session.delete, f"rules/{policies[0]['id']}")
    logger.info(f"Deleted policy {name_prefix}")


def create_policy(
    name: str,
    list_ids: list[str] | None = None,
    regex_tld: str | None = None,
) -> None:
    """Creates a gateway policy with blocking logic based on list IDs or TLD regex."""
    if list_ids:
        traffic = " or ".join([f"any(dns.domains[*] in ${list_id})" for list_id in list_ids])
        block_page_enabled = False
    else:
        traffic = f'any(dns.domains[*] matches "{regex_tld}")'
        block_page_enabled = True

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
            "rule_settings": {"block_page_enabled": block_page_enabled},
        },
    )
    logger.info(f"Created firewall policy: {name}")


def create_policy_with_tlds(name: str, tld_list: list[str]) -> None:
    """Creates a TLD-based blocking policy."""
    # Use re.escape to safely escape regex meta-characters, but Cloudflare UI
    # displays escaped hyphens (\-) which looks wrong for names like xn--... .
    # To keep correct regex semantics while avoiding escaped hyphens in the
    # displayed pattern, unescape only the hyphen escape sequence produced by
    # re.escape.
    escaped_tlds = "|".join(re.escape(tld).replace('\\-', '-') for tld in sorted(tld_list))
    regex_tld = rf"\.({escaped_tlds})$"
    create_policy(name, regex_tld=regex_tld)


def create_lists_and_policy(
    name_prefix: str,
    unique_domains: list[str],
    chunk_size: int = 1000,
) -> None:
    """Creates new lists with chunking and creates firewall policy."""
    logger.info(f"{CustomFormatter.YELLOW}Creating lists, please wait")
    list_ids = []

    for i, chunk in enumerate(chunk_list(unique_domains, chunk_size), 1):
        list_name = f"{name_prefix} {i}"
        created_list = create_list(list_name, chunk)
        list_ids.append(created_list["id"])

    create_policy(name_prefix, list_ids=list_ids)


def delete_lists_and_policy(name_prefix: str, lists: list[dict]) -> None:
    """Deletes the blocking policy and then the lists in Cloudflare."""
    delete_policy(name_prefix)
    logger.info(f"{CustomFormatter.YELLOW}Deleting lists, please wait")
    for list_item in lists:
        delete_list(list_item["id"], list_item["name"])


def chunk_list(items: list[str], chunk_size: int):
    """Yield successive chunk_size-sized chunks from items."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]
