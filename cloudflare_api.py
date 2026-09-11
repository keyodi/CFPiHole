from __future__ import annotations

from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter

from logger_config import CustomFormatter

logger = CustomFormatter.configure_logger("cloudflare")

REQUEST_TIMEOUT = 15


@dataclass(frozen=True)
class CFList:
    id: str
    name: str
    count: int = 0


@dataclass(frozen=True)
class CFPolicy:
    id: str
    name: str


class CloudflareGateway:
    """Thin typed client for the Cloudflare Zero Trust Gateway API."""

    def __init__(self, account_id: str, api_token: str) -> None:
        self._base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {api_token}"})
        self._session.mount("https://", HTTPAdapter(pool_maxsize=20, pool_connections=20))

    def _request(self, method: str, endpoint: str, json: dict | None = None):
        url = f"{self._base_url}/{endpoint}"
        try:
            response = self._session.request(method, url, json=json, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json().get("result", [])
        except requests.RequestException as exc:
            logger.error("Cloudflare API request failed: %s", exc)
            raise SystemExit(64)
        except (ValueError, KeyError) as exc:
            logger.error("Unexpected Cloudflare API response: %s", exc)
            raise SystemExit(64)

    def all_lists(self) -> list[CFList]:
        """Retrieve every list on the account."""
        data = self._request("GET", "lists") or []
        return [CFList(id=d["id"], name=d["name"], count=d.get("count", 0)) for d in data]

    def lists(self, name_prefix: str) -> list[CFList]:
        """Retrieve lists whose name starts with name_prefix."""
        return [lst for lst in self.all_lists() if lst.name.startswith(name_prefix)]

    def policy(self, name_prefix: str) -> CFPolicy | None:
        """Retrieve the single policy matching name_prefix, or None."""
        data = self._request("GET", "rules") or []
        matches = [d for d in data if d.get("name", "").startswith(name_prefix)]
        if not matches:
            return None
        if len(matches) > 1:
            raise ValueError(f"More than one policy found matching {name_prefix!r}")
        return CFPolicy(id=matches[0]["id"], name=matches[0]["name"])

    def create_list(self, name: str, domains: list[str]) -> CFList:
        """Create a named DOMAIN list."""
        payload = {
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": [{"value": domain} for domain in domains],
        }
        result = self._request("POST", "lists", json=payload)
        logger.debug("Created list %s", name)
        return CFList(id=result["id"], name=name, count=len(domains))

    def delete_list(self, cf_list: CFList) -> None:
        self._request("DELETE", f"lists/{cf_list.id}")
        logger.debug("Deleted list %s", cf_list.name)

    def delete_policy(self, name_prefix: str) -> None:
        policy = self.policy(name_prefix)
        if policy is None:
            logger.info("No firewall policy %s found to delete", name_prefix)
            return
        self._request("DELETE", f"rules/{policy.id}")
        logger.info("Deleted policy %s", name_prefix)

    def create_domain_policy(self, name: str, list_ids: list[str]) -> None:
        """Create a policy blocking DNS traffic matching any of the given lists."""
        if not list_ids:
            logger.warning("No list IDs provided, skipping policy creation: %s", name)
            return
        traffic = " or ".join(f"any(dns.domains[*] in ${lid})" for lid in list_ids)
        self._create_rule(name, traffic, block_page_enabled=False)

    def create_tld_policy(self, name: str, tlds: list[str]) -> None:
        """Create a policy blocking DNS traffic ending in any of the given TLDs."""
        regex_tld = rf"[.](|{'|'.join(tlds)})$"
        traffic = f'any(dns.domains[*] matches "{regex_tld}")'
        self._create_rule(name, traffic, block_page_enabled=True)

    def _create_rule(self, name: str, traffic: str, block_page_enabled: bool) -> None:
        payload = {
            "name": name,
            "description": "Created by script.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": block_page_enabled},
        }
        self._request("POST", "rules", json=payload)
        logger.info("Created firewall policy: %s", name)
