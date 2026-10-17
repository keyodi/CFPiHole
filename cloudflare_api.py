import logging
from typing import Any

import requests

from logger import v

log = logging.getLogger("cfpihole")
JsonDict = dict[str, Any]
DESC = "Created by CFPiHole."


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


def _req(
    session: requests.Session, method: str, url: str, payload=None
) -> JsonDict:
    try:
        response = session.request(method, url, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as error:
        raise CloudflareAPIError(f"Request failed: {error}") from error
    except ValueError as error:
        raise CloudflareAPIError(f"Invalid JSON response: {error}") from error
    if not data.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {data.get('errors')}")
    return data


def get_all(session: requests.Session, gateway: str, kind: str) -> list[JsonDict]:
    """Return every Gateway item of a kind ("lists" or "rules")."""
    data = _req(session, "GET", f"{gateway}/{kind}")
    items = data.get("result") or []
    total = (data.get("result_info") or {}).get("total_count")
    if total is not None and total > len(items):
        raise CloudflareAPIError(
            f"Incomplete response for {kind}: got {len(items)} of {total} items"
        )
    return items


def with_prefix(items: list[JsonDict], prefix: str) -> list[JsonDict]:
    return [item for item in items if item.get("name", "").startswith(prefix)]


def save_list(
    session: requests.Session,
    gateway: str,
    name: str,
    domains: list[str],
    list_id: str | None = None,
) -> str:
    """Update list_id if given, else create a DOMAIN list. Returns its ID."""
    body = {
        "name": name,
        "description": DESC,
        "items": [{"value": domain} for domain in domains],
    }
    if list_id:
        _req(session, "PUT", f"{gateway}/lists/{list_id}", body)
    else:
        body["type"] = "DOMAIN"
        result = _req(session, "POST", f"{gateway}/lists", body).get("result")
        list_id = result.get("id") if isinstance(result, dict) else None
        if not isinstance(list_id, str):
            raise CloudflareAPIError("Invalid list response: expected a string 'id'")
    log.debug("Saved list: %s (%s domains)", v(name), v(len(domains)))
    return list_id


def delete(
    session: requests.Session, gateway: str, kind: str, items: list[JsonDict]
) -> None:
    """Delete the given lists or rules (kind is "lists" or "rules")."""
    for item in items:
        _req(session, "DELETE", f"{gateway}/{kind}/{item['id']}")
        log.info("Deleted %s: %s", kind[:-1], v(item["name"]))


def domain_traffic(list_ids: list[str]) -> str:
    return " or ".join(f"any(dns.domains[*] in ${i})" for i in list_ids)


def tld_traffic(tlds: list[str]) -> str:
    return f'any(dns.domains[*] matches "[.]({"|".join(tlds)})$")'


def ensure_rule(
    session: requests.Session,
    gateway: str,
    rules: list[JsonDict],
    name: str,
    traffic: str | None,
    block_page: bool,
) -> None:
    """Make exactly one rule `name` with `traffic` exist (none if None)."""
    existing = with_prefix(rules, name)
    if traffic and len(existing) == 1:
        rule = existing[0]
        settings = rule.get("rule_settings") or {}
        if (
            rule.get("traffic") == traffic
            and rule.get("enabled", True)
            and bool(settings.get("block_page_enabled")) == block_page
        ):
            log.info("Rule unchanged — skipping: %s", v(name))
            return
    delete(session, gateway, "rules", existing)
    if traffic:
        payload = {
            "name": name,
            "description": DESC,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": block_page},
        }
        _req(session, "POST", f"{gateway}/rules", payload)
        log.info("Created rule: %s", v(name))
