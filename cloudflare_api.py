import logging
from typing import Any

import requests

from logger import v

log = logging.getLogger("cfpihole")

JsonDict = dict[str, Any]

TIMEOUT = 15
DESCRIPTION = "Created by CFPiHole."


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


def _request(
    session: requests.Session,
    method: str,
    url: str,
    json: JsonDict | None = None,
) -> JsonDict:
    """Send one request and return Cloudflare's decoded JSON response."""
    try:
        response = session.request(method, url, json=json, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise CloudflareAPIError(f"Request failed: {exc}") from exc
    except ValueError as exc:
        raise CloudflareAPIError(f"Invalid JSON response: {exc}") from exc

    if not data.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {data.get('errors')}")
    return data


def _get_all(session: requests.Session, url: str) -> list[JsonDict]:
    """GET a Gateway collection (Cloudflare returns it in a single response)."""
    data = _request(session, "GET", url)
    items = data.get("result") or []
    total = (data.get("result_info") or {}).get("total_count")
    if total is not None and total > len(items):
        raise CloudflareAPIError(
            f"Incomplete response from {url}: got {len(items)} of {total} items"
        )
    return items


def get_lists(session: requests.Session, base: str) -> list[JsonDict]:
    """Return every Gateway list in the account."""
    return _get_all(session, f"{base}/lists")


def lists_with_prefix(lists: list[JsonDict], prefix: str) -> list[JsonDict]:
    """Return the lists in an already-fetched snapshot named with prefix."""
    return [item for item in lists if item.get("name", "").startswith(prefix)]


def _list_body(name: str, domains: list[str]) -> JsonDict:
    """Request body shared by list creation and update."""
    return {
        "name": name,
        "description": DESCRIPTION,
        "items": [{"value": domain} for domain in domains],
    }


def create_list(
    session: requests.Session, base: str, name: str, domains: list[str]
) -> str:
    """Create a DOMAIN list and return its Cloudflare list ID."""
    data = _request(
        session,
        "POST",
        f"{base}/lists",
        json={**_list_body(name, domains), "type": "DOMAIN"},
    )
    result = data.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("id"), str):
        raise CloudflareAPIError("Invalid list response: expected a string 'id'")
    log.debug("Created list: %s (%s domains)", v(name), v(len(domains)))
    return result["id"]


def update_list(
    session: requests.Session,
    base: str,
    list_id: str,
    name: str,
    domains: list[str],
) -> None:
    """Replace an existing list's items with one PUT."""
    _request(
        session,
        "PUT",
        f"{base}/lists/{list_id}",
        json=_list_body(name, domains),
    )
    log.debug("Updated list: %s (%s domains)", v(name), v(len(domains)))


def delete_lists(
    session: requests.Session, base: str, lists: list[JsonDict]
) -> None:
    """Delete exactly the given lists, one at a time."""
    for item in lists:
        _request(session, "DELETE", f"{base}/lists/{item['id']}")
        log.debug("Deleted list: %s", v(item["name"]))


def get_rules(session: requests.Session, base: str) -> list[JsonDict]:
    """Return every Gateway DNS rule in the account."""
    return _get_all(session, f"{base}/rules")


def rules_with_prefix(rules: list[JsonDict], prefix: str) -> list[JsonDict]:
    """Return the rules in an already-fetched snapshot named with prefix."""
    return [rule for rule in rules if rule.get("name", "").startswith(prefix)]


def domain_traffic(list_ids: list[str]) -> str:
    """Traffic expression matching any of list_ids."""
    return " or ".join(
        f"any(dns.domains[*] in ${list_id})" for list_id in list_ids
    )


def tld_traffic(tlds: list[str]) -> str:
    """Traffic expression matching any of the given TLDs."""
    pattern = "|".join(tlds)
    return f'any(dns.domains[*] matches "[.]({pattern})$")'


def rule_matches(
    rule: JsonDict, traffic: str, block_page_enabled: bool
) -> bool:
    """Return True if an existing rule is already what we would create."""
    settings = rule.get("rule_settings") or {}
    return (
        rule.get("traffic") == traffic
        and rule.get("enabled", True)
        and bool(settings.get("block_page_enabled")) == block_page_enabled
    )


def create_rule(
    session: requests.Session,
    base: str,
    name: str,
    traffic: str,
    block_page_enabled: bool,
) -> None:
    """Create a DNS block rule for the given traffic expression."""
    _request(
        session,
        "POST",
        f"{base}/rules",
        json={
            "name": name,
            "description": DESCRIPTION,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": block_page_enabled},
        },
    )
    log.info("Created rule: %s", v(name))


def delete_rules(
    session: requests.Session, base: str, rules: list[JsonDict]
) -> None:
    """Delete exactly the given rules, one at a time."""
    for rule in rules:
        _request(session, "DELETE", f"{base}/rules/{rule['id']}")
        log.info("Deleted rule: %s", v(rule["name"]))
