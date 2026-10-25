import logging
from typing import Any

import requests

from logger import highlight

JsonDict = dict[str, Any]

ITEM_DESCRIPTION = "Created by CFPiHole."
REQUEST_TIMEOUT_SECONDS = 15

log = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


def _request(
    session: requests.Session,
    method: str,
    url: str,
    payload: JsonDict | None = None,
) -> JsonDict:
    """Send a request and return the decoded JSON body, or raise on failure."""
    try:
        response = session.request(
            method, url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        response_body = response.json()
    except requests.RequestException as request_error:
        raise CloudflareAPIError(f"Request failed: {request_error}") from request_error
    except ValueError as json_error:
        raise CloudflareAPIError(f"Invalid JSON response: {json_error}") from json_error

    if not response_body.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {response_body.get('errors')}")
    return response_body


def get_all_items(
    session: requests.Session, gateway_url: str, item_kind: str
) -> list[JsonDict]:
    """Return every Gateway item of a kind ("lists" or "rules")."""
    response_body = _request(session, "GET", f"{gateway_url}/{item_kind}")

    items = response_body.get("result") or []
    total_count = (response_body.get("result_info") or {}).get("total_count")

    if total_count is not None and total_count > len(items):
        raise CloudflareAPIError(
            f"Incomplete response for {item_kind}: "
            f"got {len(items)} of {total_count} items"
        )
    return items


def filter_by_prefix(items: list[JsonDict], name_prefix: str) -> list[JsonDict]:
    """Return the items whose name starts with `name_prefix`."""
    return [item for item in items if item.get("name", "").startswith(name_prefix)]


def delete_items(
    session: requests.Session,
    gateway_url: str,
    item_kind: str,
    items: list[JsonDict],
) -> None:
    """Delete the given lists or rules (`item_kind` is "lists" or "rules")."""
    for item in items:
        _request(session, "DELETE", f"{gateway_url}/{item_kind}/{item['id']}")
        log.debug("Deleted %s: %s", item_kind.removesuffix("s"), highlight(item["name"]))


def save_list(
    session: requests.Session,
    gateway_url: str,
    list_name: str,
    domains: list[str],
    existing_list_id: str | None = None,
) -> str:
    """Update `existing_list_id` if given, else create a DOMAIN list."""
    log.debug(
        "Saving list: %s (%s domains)", highlight(list_name), highlight(len(domains))
    )

    list_payload = {
        "name": list_name,
        "description": ITEM_DESCRIPTION,
        "items": [{"value": domain} for domain in domains],
    }

    if existing_list_id:
        _request(session, "PUT", f"{gateway_url}/lists/{existing_list_id}", list_payload)
        return existing_list_id

    list_payload["type"] = "DOMAIN"
    create_response = _request(session, "POST", f"{gateway_url}/lists", list_payload)
    return create_response["result"]["id"]


def build_domain_traffic(list_ids: list[str]) -> str:
    """Build a traffic expression matching DNS queries for any of the lists."""
    return " or ".join(f"any(dns.domains[*] in ${list_id})" for list_id in list_ids)


def build_tld_traffic(tlds: list[str]) -> str:
    """Build a traffic expression matching DNS queries ending in any TLD."""
    return f'any(dns.domains[*] matches "[.]({"|".join(tlds)})$")'


def ensure_rule(
    session: requests.Session,
    gateway_url: str,
    rule_name: str,
    traffic_expression: str | None,
    block_page_enabled: bool,
) -> None:
    """Make exactly one rule `rule_name` with `traffic_expression` exist."""
    all_rules = get_all_items(session, gateway_url, "rules")
    existing_rules = filter_by_prefix(all_rules, rule_name)

    # Nothing to do if the single existing rule is already correct.
    if traffic_expression and len(existing_rules) == 1:
        existing_rule = existing_rules[0]
        existing_settings = existing_rule.get("rule_settings") or {}
        if (
            existing_rule.get("traffic") == traffic_expression
            and existing_rule.get("enabled", True)
            and bool(existing_settings.get("block_page_enabled")) == block_page_enabled
        ):
            log.info("Rule unchanged — skipping: %s", highlight(rule_name))
            return

    # Otherwise remove the old rule(s) and, if wanted, create a fresh one.
    delete_items(session, gateway_url, "rules", existing_rules)

    if traffic_expression:
        rule_payload = {
            "name": rule_name,
            "description": ITEM_DESCRIPTION,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic_expression,
            "rule_settings": {"block_page_enabled": block_page_enabled},
        }
        _request(session, "POST", f"{gateway_url}/rules", rule_payload)
        log.info("Created rule: %s", highlight(rule_name))
