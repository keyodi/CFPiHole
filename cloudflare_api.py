import logging
from typing import Any

import requests

from logger import highlight

JsonDict = dict[str, Any]

API_URL = "https://api.cloudflare.com/client/v4"
DESCRIPTION = "Created by CFPiHole."
TIMEOUT = 15

AD_PREFIX = "[CFPiHole] Block Ads"
TLD_PREFIX = "[CFPiHole] Block TLDs"

MAX_LISTS = 300
MAX_DOMAINS = 1000

logger = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure."""
    pass


def create_session(token: str) -> requests.Session:
    """Return a session that authenticates every request with `token`."""
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    return session


def build_base_url(account_id: str) -> str:
    """Return the Gateway API base URL for an account."""
    return f"{API_URL}/accounts/{account_id}/gateway"


def request(
    session: requests.Session,
    method: str,
    url: str,
    payload: JsonDict | None = None,
) -> JsonDict:
    """Send a request and return the decoded JSON body, or raise on failure."""
    try:
        response = session.request(method, url, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        body = response.json()
    except requests.RequestException as exc:
        raise CloudflareAPIError(f"Request failed: {exc}") from exc
    except ValueError as exc:
        raise CloudflareAPIError(f"Invalid JSON response: {exc}") from exc

    if not body.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {body.get('errors')}")
    return body


def get_items(session: requests.Session, base_url: str, kind: str) -> list[JsonDict]:
    """Return every Gateway item of a kind ("lists" or "rules")."""
    body = request(session, "GET", f"{base_url}/{kind}")
    items = body.get("result") or []
    total = (body.get("result_info") or {}).get("total_count")

    if total is not None and total > len(items):
        raise CloudflareAPIError(
            f"Incomplete response for {kind}: got {len(items)} of {total} items"
        )
    return items


def filter_by_prefix(items: list[JsonDict], prefix: str) -> list[JsonDict]:
    """Return the items whose name starts with `prefix`."""
    return [item for item in items if item.get("name", "").startswith(prefix)]


def check_list_limit(cf_lists: list[JsonDict], needed: int) -> bool:
    """Return whether replacing managed lists with `needed` stays within the limit."""
    managed = len(filter_by_prefix(cf_lists, AD_PREFIX))
    others = len(cf_lists) - managed
    return needed + others <= MAX_LISTS


def delete_items(
    session: requests.Session,
    base_url: str,
    kind: str,
    items: list[JsonDict],
) -> None:
    """Delete the given lists or rules (`kind` is "lists" or "rules")."""
    for item in items:
        request(session, "DELETE", f"{base_url}/{kind}/{item['id']}")
        logger.debug(f"Deleted {kind.removesuffix('s')}: {highlight(item['name'])}")


def save_list(
    session: requests.Session,
    base_url: str,
    name: str,
    domains: list[str],
    list_id: str | None = None,
) -> str:
    """Update `list_id` if given, else create a DOMAIN list."""
    logger.debug(f"Saving list: {highlight(name)} ({highlight(len(domains))} domains)")

    payload = {
        "name": name,
        "description": DESCRIPTION,
        "items": [{"value": domain} for domain in domains],
    }

    if list_id:
        request(session, "PUT", f"{base_url}/lists/{list_id}", payload)
        return list_id

    payload["type"] = "DOMAIN"
    body = request(session, "POST", f"{base_url}/lists", payload)
    return body["result"]["id"]


def build_list_traffic(list_ids: list[str]) -> str:
    """Build a traffic expression matching DNS queries for any of the lists."""
    return " or ".join(f"any(dns.domains[*] in ${i})" for i in list_ids)


def build_tld_traffic(tlds: list[str]) -> str:
    """Build a traffic expression matching DNS queries ending in any TLD."""
    tld_pattern = "|".join(tlds)
    return f'any(dns.domains[*] matches "[.]({tld_pattern})$")'


def ensure_policy(
    session: requests.Session,
    base_url: str,
    name: str,
    traffic: str | None,
    block_page: bool,
) -> None:
    """Make exactly one policy `name` with `traffic` exist."""
    cf_policies = get_items(session, base_url, "rules")
    policies = filter_by_prefix(cf_policies, name)

    if traffic and len(policies) == 1:
        policy = policies[0]
        settings = policy.get("rule_settings") or {}
        if (
            policy.get("traffic") == traffic
            and policy.get("enabled", True)
            and bool(settings.get("block_page_enabled")) == block_page
        ):
            logger.info(f"Policy unchanged — skipping: {highlight(name)}")
            return

    delete_items(session, base_url, "rules", policies)

    if traffic:
        payload = {
            "name": name,
            "description": DESCRIPTION,
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": block_page},
        }
        request(session, "POST", f"{base_url}/rules", payload)
        logger.info(f"Created policy: {highlight(name)}")


def sync_lists(
    session: requests.Session,
    base_url: str,
    chunks: list[list[str]],
    cf_lists: list[JsonDict],
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one policy."""
    cf_by_name = {item["name"]: item for item in filter_by_prefix(cf_lists, AD_PREFIX)}
    names = [f"{AD_PREFIX} {i}" for i in range(1, len(chunks) + 1)]

    surplus = [item for name, item in cf_by_name.items() if name not in names]
    if surplus:
        ensure_policy(session, base_url, AD_PREFIX, None, False)
        delete_items(session, base_url, "lists", surplus)

    if chunks:
        logger.info(f"Creating/updating {highlight(len(chunks))} lists, please wait")

    list_ids = []
    for name, domains in zip(names, chunks):
        current = cf_by_name.get(name)
        list_ids.append(
            save_list(session, base_url, name, domains, current["id"] if current else None)
        )

    traffic = build_list_traffic(list_ids) if list_ids else None
    ensure_policy(session, base_url, AD_PREFIX, traffic, False)
