import logging

import requests

from logger import v

log = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure — caught in main.py for exit code 64."""


def _request(session, method, url, json=None):
    try:
        r = session.request(method, url, json=json, timeout=15)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as exc:
        raise CloudflareAPIError(f"Request failed: {exc}") from exc
    if not data.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {data.get('errors')}")
    return data.get("result", [])


def get_lists(session, base):
    return _request(session, "GET", f"{base}/lists") or []


def get_rules(session, base):
    return _request(session, "GET", f"{base}/rules") or []


def delete_rule(session, base, name_prefix):
    for rule in get_rules(session, base):
        if rule.get("name", "").startswith(name_prefix):
            _request(session, "DELETE", f"{base}/rules/{rule['id']}")
            log.info("Deleted rule: %s", v(rule["name"]))


def delete_lists_by_prefix(session, base, prefix):
    for lst in get_lists(session, base):
        if lst["name"].startswith(prefix):
            _request(session, "DELETE", f"{base}/lists/{lst['id']}")
            log.info("Deleted list: %s", v(lst["name"]))


def create_list(session, base, name, domains):
    result = _request(session, "POST", f"{base}/lists", json={
        "name": name,
        "description": "Created by CFPiHole.",
        "type": "DOMAIN",
        "items": [{"value": d} for d in domains],
    })
    log.info("Created list: %s (%s domains)", v(name), v(len(domains)))
    return result["id"]


def create_domain_rule(session, base, name, list_ids):
    traffic = " or ".join(f"any(dns.domains[*] in ${lid})" for lid in list_ids)
    _request(session, "POST", f"{base}/rules", json={
        "name": name,
        "description": "Created by CFPiHole.",
        "action": "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": traffic,
        "rule_settings": {"block_page_enabled": False},
    })
    log.info("Created domain rule: %s", v(name))


def create_tld_rule(session, base, name, tlds):
    regex = rf"[.](|{'|'.join(tlds)})$"
    traffic = f'any(dns.domains[*] matches "{regex}")'
    _request(session, "POST", f"{base}/rules", json={
        "name": name,
        "description": "Created by CFPiHole.",
        "action": "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": traffic,
        "rule_settings": {"block_page_enabled": True},
    })
    log.info("Created TLD rule: %s", v(name))
