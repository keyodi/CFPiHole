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

# Cloudflare Zero Trust account limits.
MAX_LISTS = 300
MAX_DOMAINS = 1000

logger = logging.getLogger("cfpihole")


class CloudflareAPIError(Exception):
    """Raised on any Cloudflare API failure (main.py exits with code 64)."""


def create_session(token: str) -> requests.Session:
    """Return a session that authenticates every request with `token`."""
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    return session


def build_base_url(account_id: str) -> str:
    """Return the Gateway API base URL for an account."""
    return f"{API_URL}/accounts/{account_id}/gateway"


def _request(
    session: requests.Session,
    method: str,
    url: str,
    payload: JsonDict | None = None,
) -> JsonDict:
    """Send a request and return the decoded JSON body, or raise on failure."""
    try:
        r = session.request(method, url, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        body = r.json()
    except requests.RequestException as e:
        raise CloudflareAPIError(f"Request failed: {e}") from e
    except ValueError as e:
        raise CloudflareAPIError(f"Invalid JSON response: {e}") from e

    if not body.get("success", True):
        raise CloudflareAPIError(f"Cloudflare API error: {body.get('errors')}")
    return body


def get_items(session: requests.Session, base_url: str, kind: str) -> list[JsonDict]:
    """Return every Gateway item of a kind ("lists" or "rules")."""
    body = _request(session, "GET", f"{base_url}/{kind}")

    items = body.get("result") or []
    total = (body.get("result_info") or {}).get("total_count")

    if total is not None and total > len(items):
        raise CloudflareAPIError(
            f"Incomplete response for {kind}: got {len(items)} of {total} items"
        )
    return items


def filter_by_prefix(items: list[JsonDict], prefix: str) -> list[JsonDict]:
    """Return the items whose name starts with `prefix`."""
    return [i for i in items if i.get("name", "").startswith(prefix)]


def check_list_limit(cf_lists: list[JsonDict], needed: int) -> None:
    """Raise if `needed` managed lists would exceed the account limit.

    Lists not managed by this tool count against the limit but are never
    touched, so only the managed ones are replaced by `needed`.
    """
    managed = len(filter_by_prefix(cf_lists, AD_PREFIX))
    others = len(cf_lists) - managed
    if needed + others > MAX_LISTS:
        raise CloudflareAPIError(
            f"Would exceed {MAX_LISTS} list limit — use smaller block lists"
        )


def delete_items(
    session: requests.Session,
    base_url: str,
    kind: str,
    items: list[JsonDict],
) -> None:
    """Delete the given lists or rules (`kind` is "lists" or "rules")."""
    for item in items:
        _request(session, "DELETE", f"{base_url}/{kind}/{item['id']}")
        logger.debug("Deleted %s: %s", kind.removesuffix("s"), highlight(item["name"]))


def save_list(
    session: requests.Session,
    base_url: str,
    name: str,
    domains: list[str],
    list_id: str | None = None,
) -> str:
    """Update `list_id` if given, else create a DOMAIN list."""
    logger.debug(
        "Saving list: %s (%s domains)", highlight(name), highlight(len(domains))
    )

    payload = {
        "name": name,
        "description": DESCRIPTION,
        "items": [{"value": d} for d in domains],
    }

    if list_id:
        _request(session, "PUT", f"{base_url}/lists/{list_id}", payload)
        return list_id

    payload["type"] = "DOMAIN"
    body = _request(session, "POST", f"{base_url}/lists", payload)
    return body["result"]["id"]


def build_list_traffic(list_ids: list[str]) -> str:
    """Build a traffic expression matching DNS queries for any of the lists."""
    return " or ".join(f"any(dns.domains[*] in ${i})" for i in list_ids)


def build_tld_traffic(tlds: list[str]) -> str:
    """Build a traffic expression matching DNS queries ending in any TLD."""
    return f'any(dns.domains[*] matches "[.]({"|".join(tlds)})$")'


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

    # Nothing to do if the single existing policy is already correct.
    if traffic and len(policies) == 1:
        policy = policies[0]
        settings = policy.get("rule_settings") or {}
        if (
            policy.get("traffic") == traffic
            and policy.get("enabled", True)
            and bool(settings.get("block_page_enabled")) == block_page
        ):
            logger.info("Policy unchanged — skipping: %s", highlight(name))
            return

    # Otherwise remove the old policies and, if wanted, create a fresh one.
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
        _request(session, "POST", f"{base_url}/rules", payload)
        logger.info("Created policy: %s", highlight(name))


def sync_lists(
    session: requests.Session,
    base_url: str,
    chunks: list[list[str]],
    cf_lists: list[JsonDict],
) -> None:
    """Make Cloudflare hold exactly one list per chunk, plus one policy."""
    cf_by_name = {l["name"]: l for l in filter_by_prefix(cf_lists, AD_PREFIX)}
    names = [f"{AD_PREFIX} {i}" for i in range(1, len(chunks) + 1)]

    surplus = [l for name, l in cf_by_name.items() if name not in names]
    if surplus:
        # Drop the policy first so it never references a deleted list.
        ensure_policy(session, base_url, AD_PREFIX, None, False)
        delete_items(session, base_url, "lists", surplus)

    if chunks:
        logger.info("Updating lists, please wait")

    list_ids = []
    for name, domains in zip(names, chunks):
        cf_list = cf_by_name.get(name)
        list_id = cf_list["id"] if cf_list else None
        list_ids.append(save_list(session, base_url, name, domains, list_id))

    traffic = build_list_traffic(list_ids) if list_ids else None
    ensure_policy(session, base_url, AD_PREFIX, traffic, False)
