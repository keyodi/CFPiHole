import logging
from concurrent.futures import ThreadPoolExecutor

import requests

from logger import v

log = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure.

    The exception is caught in main.py and results in exit code 64.
    """


def _request(session, method, url, json=None):
    try:
        response = session.request(method, url, json=json, timeout=15)
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
    return data.get("result", [])


def _get_paginated(session, base, path, per_page=50, max_pages=100):
    """Fetch every page of a Cloudflare Gateway list endpoint."""
    results = []
    seen_ids = set()
    page = 1
    while page <= max_pages:
        try:
            response = session.get(
                f"{base}/{path}",
                params={"page": page, "per_page": per_page},
                timeout=15,
            )
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
        log.warning("Stopped paginating %s after %s pages", path, max_pages)

    return results


def get_lists(session, base):
    return _get_paginated(session, base, "lists")


def get_rules(session, base):
    return _get_paginated(session, base, "rules")


def delete_rule(session, base, name_prefix):
    for rule in get_rules(session, base):
        if rule.get("name", "").startswith(name_prefix):
            _request(session, "DELETE", f"{base}/rules/{rule['id']}")
            log.info("Deleted rule: %s", v(rule["name"]))


def delete_lists_by_prefix(session, base, prefix, lists=None):
    for item in lists if lists is not None else get_lists(session, base):
        if item["name"].startswith(prefix):
            _request(session, "DELETE", f"{base}/lists/{item['id']}")
            log.info("Deleted list: %s", v(item["name"]))


def create_list(session, base, name, domains):
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
    log.info("Created list: %s (%s domains)", v(name), v(len(domains)))
    return result["id"]


def create_lists(session, base, name_prefix, chunks):
    """Create one list per chunk concurrently, preserving chunk order."""
    workers = max(1, min(len(chunks), 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(
            pool.map(
                lambda item: create_list(
                    session, base, f"{name_prefix} {item[0]}", item[1]
                ),
                enumerate(chunks, 1),
            )
        )


def create_domain_rule(session, base, name, list_ids):
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


def create_tld_rule(session, base, name, tlds):
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
