import logging
from typing import Any, cast

import requests

from logger import v

log = logging.getLogger("cfpihole")

JsonDict = dict[str, Any]

MAX_LIST_ITEMS = 1000


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure.

    The exception is caught in main.py and results in exit code 64.
    """


def _parse_response(response: requests.Response) -> Any:
    """Shared response handling: JSON-decode and check Cloudflare's
    'success' envelope. Raises CloudflareAPIError on any problem.
    """
    try:
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise CloudflareAPIError(f"Request failed: {exc}") from exc
    except ValueError as exc:
        raise CloudflareAPIError(f"Invalid JSON response: {exc}") from exc

    if not data.get("success", True):
        raise CloudflareAPIError(
            f"Cloudflare API error: {data.get('errors')}"
        )
    return data


def _request(
    session: requests.Session,
    method: str,
    url: str,
    json: JsonDict | None = None,
) -> Any:
    """Make a single Cloudflare API request and return its 'result'."""
    try:
        response = session.request(method, url, json=json, timeout=15)
    except requests.RequestException as exc:
        raise CloudflareAPIError(f"Request failed: {exc}") from exc
    data = _parse_response(response)
    return data.get("result", [])


def _get_paginated(
    session: requests.Session,
    base: str,
    path: str,
    per_page: int = 50,
    max_pages: int = 100,
) -> list[JsonDict]:
    """Fetch every page of a Cloudflare Gateway list endpoint."""
    results: list[JsonDict] = []
    seen_ids: set[Any] = set()
    page = 1
    while page <= max_pages:
        try:
            response = session.get(
                f"{base}/{path}",
                params={"page": page, "per_page": per_page},
                timeout=15,
            )
        except requests.RequestException as exc:
            raise CloudflareAPIError(f"Request failed: {exc}") from exc
        data = _parse_response(response)

        chunk = data.get("result") or []
        new_items = [item for item in chunk if item.get("id") not in seen_ids]

        if not new_items:
            # Empty page, or the same items came back again — either way
            # there is nothing more to collect.
            break

        results.extend(new_items)
        seen_ids.update(item.get("id") for item in new_items)

        total = (data.get("result_info") or {}).get("total_count")
        done = len(chunk) < per_page or (
            total is not None and len(results) >= total
        )
        if done:
            break
        page += 1
    else:
        raise CloudflareAPIError(
            f"Stopped paginating {path} after {max_pages} pages "
            "— result set may be incomplete"
        )

    return results


def get_lists(session: requests.Session, base: str) -> list[JsonDict]:
    """Return every Gateway list in the account."""
    return _get_paginated(session, base, "lists")


def get_rules(session: requests.Session, base: str) -> list[JsonDict]:
    """Return every Gateway DNS rule in the account."""
    return _get_paginated(session, base, "rules")


def delete_rule(
    session: requests.Session, base: str, name_prefix: str
) -> None:
    """Delete every rule whose name starts with name_prefix."""
    for rule in get_rules(session, base):
        if rule.get("name", "").startswith(name_prefix):
            _request(session, "DELETE", f"{base}/rules/{rule['id']}")
            log.info("Deleted rule: %s", v(rule["name"]))


def delete_lists_by_prefix(
    session: requests.Session,
    base: str,
    prefix: str,
    lists: list[JsonDict] | None = None,
) -> None:
    """Delete every list whose name starts with prefix."""
    for item in lists if lists is not None else get_lists(session, base):
        if item["name"].startswith(prefix):
            _request(session, "DELETE", f"{base}/lists/{item['id']}")
            log.debug("Deleted list: %s", v(item["name"]))


def create_list(
    session: requests.Session, base: str, name: str, domains: list[str]
) -> str:
    """Create a DOMAIN list and return its Cloudflare list ID."""
    if len(domains) > MAX_LIST_ITEMS:
        raise ValueError(
            f"{name}: {len(domains)} domains exceeds the "
            f"{MAX_LIST_ITEMS}-item chunk size"
        )
    result = _request(
        session,
        "POST",
        f"{base}/lists",
        json={
            "name": name,
            "description": "Created by CFPiHole.",
            "type": "DOMAIN",
            "items": [{"value": domain} for domain in domains],
        },
    )
    log.debug("Created list: %s (%s domains)", v(name), v(len(domains)))
    return cast(str, result["id"])


def create_domain_rule(
    session: requests.Session, base: str, name: str, list_ids: list[str]
) -> None:
    """Create a DNS rule that blocks traffic matching any of list_ids."""
    if not list_ids:
        return
    traffic = " or ".join(
        f"any(dns.domains[*] in ${list_id})" for list_id in list_ids
    )
    _request(
        session,
        "POST",
        f"{base}/rules",
        json={
            "name": name,
            "description": "Created by CFPiHole.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": False},
        },
    )
    log.info("Created domain rule: %s", v(name))


def create_tld_rule(
    session: requests.Session, base: str, name: str, tlds: list[str]
) -> None:
    """Create a DNS rule that blocks traffic to the given TLDs."""
    regex = rf"[.](|{'|'.join(tlds)})$"
    traffic = f'any(dns.domains[*] matches "{regex}")'
    _request(
        session,
        "POST",
        f"{base}/rules",
        json={
            "name": name,
            "description": "Created by CFPiHole.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": True},
        },
    )
    log.info("Created TLD rule: %s", v(name))
