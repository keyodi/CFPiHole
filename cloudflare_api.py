import logging
from typing import Any

import requests

from logger import v

log = logging.getLogger("cfpihole")

JsonDict = dict[str, Any]

REQUEST_TIMEOUT_SECONDS = 15
DESCRIPTION = "Created by CFPiHole."


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


def _request(
    session: requests.Session,
    method: str,
    url: str,
    payload: JsonDict | None = None,
) -> JsonDict:
    """Send one request and return Cloudflare's decoded JSON response."""
    try:
        response = session.request(
            method, url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        response_data = response.json()
    except requests.RequestException as error:
        raise CloudflareAPIError(f"Request failed: {error}") from error
    except ValueError as error:
        raise CloudflareAPIError(f"Invalid JSON response: {error}") from error

    if not response_data.get("success", True):
        raise CloudflareAPIError(
            f"Cloudflare API error: {response_data.get('errors')}"
        )
    return response_data


def get_all(
    session: requests.Session, gateway_url: str, kind: str
) -> list[JsonDict]:
    """Return every Gateway item of a kind ("lists" or "rules")."""
    response_data = _request(session, "GET", f"{gateway_url}/{kind}")
    items = response_data.get("result") or []
    result_info = response_data.get("result_info") or {}
    total_count = result_info.get("total_count")
    if total_count is not None and total_count > len(items):
        raise CloudflareAPIError(
            f"Incomplete response for {kind}: "
            f"got {len(items)} of {total_count} items"
        )
    return items


def with_prefix(items: list[JsonDict], prefix: str) -> list[JsonDict]:
    """Return the lists or rules whose name starts with prefix."""
    return [item for item in items if item.get("name", "").startswith(prefix)]


def create_list(
    session: requests.Session,
    gateway_url: str,
    name: str,
    domains: list[str],
) -> str:
    """Create a DOMAIN list and return its Cloudflare list ID."""
    payload = {
        "name": name,
        "description": DESCRIPTION,
        "type": "DOMAIN",
        "items": [{"value": domain} for domain in domains],
    }
    response_data = _request(
        session, "POST", f"{gateway_url}/lists", payload=payload
    )
    created_list = response_data.get("result")
    if not isinstance(created_list, dict) or not isinstance(
        created_list.get("id"), str
    ):
        raise CloudflareAPIError(
            "Invalid list response: expected a string 'id'"
        )
    log.debug("Created list: %s (%s domains)", v(name), v(len(domains)))
    return created_list["id"]


def update_list(
    session: requests.Session,
    gateway_url: str,
    list_id: str,
    name: str,
    domains: list[str],
) -> None:
    """Replace an existing list's items."""
    payload = {
        "name": name,
        "description": DESCRIPTION,
        "items": [{"value": domain} for domain in domains],
    }
    _request(
        session, "PUT", f"{gateway_url}/lists/{list_id}", payload=payload
    )
    log.debug("Updated list: %s (%s domains)", v(name), v(len(domains)))


def delete_lists(
    session: requests.Session, gateway_url: str, lists: list[JsonDict]
) -> None:
    """Delete the given lists."""
    for gateway_list in lists:
        _request(
            session, "DELETE", f"{gateway_url}/lists/{gateway_list['id']}"
        )
        log.debug("Deleted list: %s", v(gateway_list["name"]))


def domain_traffic(list_ids: list[str]) -> str:
    """Traffic expression matching any of list_ids."""
    return " or ".join(
        f"any(dns.domains[*] in ${list_id})" for list_id in list_ids
    )


def tld_traffic(tlds: list[str]) -> str:
    """Traffic expression matching any of the given TLDs."""
    tld_pattern = "|".join(tlds)
    return f'any(dns.domains[*] matches "[.]({tld_pattern})$")'


def rule_matches(
    rule: JsonDict, traffic: str, block_page_enabled: bool
) -> bool:
    """Return True if an existing rule is already what we would create."""
    rule_settings = rule.get("rule_settings") or {}
    return (
        rule.get("traffic") == traffic
        and rule.get("enabled", True)
        and bool(rule_settings.get("block_page_enabled")) == block_page_enabled
    )


def create_rule(
    session: requests.Session,
    gateway_url: str,
    name: str,
    traffic: str,
    block_page_enabled: bool,
) -> None:
    """Create a DNS block rule for the given traffic expression."""
    payload = {
        "name": name,
        "description": DESCRIPTION,
        "action": "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": traffic,
        "rule_settings": {"block_page_enabled": block_page_enabled},
    }
    _request(session, "POST", f"{gateway_url}/rules", payload=payload)
    log.info("Created rule: %s", v(name))


def delete_rules(
    session: requests.Session, gateway_url: str, rules: list[JsonDict]
) -> None:
    """Delete the given rules."""
    for rule in rules:
        _request(session, "DELETE", f"{gateway_url}/rules/{rule['id']}")
        log.info("Deleted rule: %s", v(rule["name"]))
