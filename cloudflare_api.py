import logging
from typing import Any

import requests

from logger import v as highlight

# ─────────────────────────────── Constants ────────────────────────────────

JsonDict = dict[str, Any]

DESCRIPTION = "Created by CFPiHole."
REQUEST_TIMEOUT_SECONDS = 15

log = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


# ───────────────────────────── Low-level request ──────────────────────────

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
        raise CloudflareAPIError(
            f"Cloudflare API error: {response_body.get('errors')}"
        )
    return response_body


# ───────────────────────────── Reading & filtering ────────────────────────

def get_all(
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


def with_prefix(items: list[JsonDict], name_prefix: str) -> list[JsonDict]:
    """Return the items whose name starts with `name_prefix`."""
    return [item for item in items if item.get("name", "").startswith(name_prefix)]


# ──────────────────────────────── Lists ───────────────────────────────────

def save_list(
    session: requests.Session,
    gateway_url: str,
    list_name: str,
    domains: list[str],
    existing_list_id: str | None = None,
) -> str:
    """Update `existing_list_id` if given, else create a DOMAIN list.

    Returns the list's ID.
    """
    list_body = {
        "name": list_name,
        "description": DESCRIPTION,
        "items": [{"value": domain} for domain in domains],
    }

    if existing_list_id:
        _request(session, "PUT", f"{gateway_url}/lists/{existing_list_id}", list_body)
        list_id = existing_list_id
    else:
        list_body["type"] = "DOMAIN"
        created = _request(session, "POST", f"{gateway_url}/lists", list_body)
        result = created.get("result")
        list_id = result.get("id") if isinstance(result, dict) else None
        if not isinstance(list_id, str):
            raise CloudflareAPIError("Invalid list response: expected a string 'id'")

    log.debug(
        "Saved list: %s (%s domains)", highlight(list_name), highlight(len(domains))
    )
    return list_id


def delete(
    session: requests.Session,
    gateway_url: str,
    item_kind: str,
    items: list[JsonDict],
) -> None:
    """Delete the given lists or rules (`item_kind` is "lists" or "rules")."""
    singular_kind = item_kind[:-1]  # "lists" -> "list"
    for item in items:
        _request(session, "DELETE", f"{gateway_url}/{item_kind}/{item['id']}")
        log.info("Deleted %s: %s", singular_kind, highlight(item["name"]))


# ──────────────────────────── Traffic expressions ─────────────────────────

def domain_traffic(list_ids: list[str]) -> str:
    """Build a traffic expression matching DNS queries for any of the lists."""
    return " or ".join(f"any(dns.domains[*] in ${list_id})" for list_id in list_ids)


def tld_traffic(tlds: list[str]) -> str:
    """Build a traffic expression matching DNS queries ending in any TLD."""
    tld_pattern = "|".join(tlds)
    return f'any(dns.domains[*] matches "[.]({tld_pattern})$")'


# ──────────────────────────────── Rules ───────────────────────────────────

def _rule_is_up_to_date(
    rule: JsonDict, traffic_expression: str, block_page_enabled: bool
) -> bool:
    """Return True if `rule` already matches the wanted traffic and settings."""
    rule_settings = rule.get("rule_settings") or {}
    return (
        rule.get("traffic") == traffic_expression
        and rule.get("enabled", True)
        and bool(rule_settings.get("block_page_enabled")) == block_page_enabled
    )


def ensure_rule(
    session: requests.Session,
    gateway_url: str,
    gateway_rules: list[JsonDict],
    rule_name: str,
    traffic_expression: str | None,
    block_page_enabled: bool,
) -> None:
    """Make exactly one rule `rule_name` with `traffic_expression` exist.

    If `traffic_expression` is None, any matching rules are removed instead.
    """
    existing_rules = with_prefix(gateway_rules, rule_name)

    # Nothing to do if the single existing rule is already correct.
    if (
        traffic_expression
        and len(existing_rules) == 1
        and _rule_is_up_to_date(
            existing_rules[0], traffic_expression, block_page_enabled
        )
    ):
        log.info("Rule unchanged — skipping: %s", highlight(rule_name))
        return

    # Otherwise remove the old rule(s) and, if wanted, create a fresh one.
    delete(session, gateway_url, "rules", existing_rules)

    if traffic_expression:
        rule_payload = {
            "name": rule_name,
            "description": DESCRIPTION,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic_expression,
            "rule_settings": {"block_page_enabled": block_page_enabled},
        }
        _request(session, "POST", f"{gateway_url}/rules", rule_payload)
        log.info("Created rule: %s", highlight(rule_name))
