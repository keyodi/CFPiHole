"""Cloudflare API client helpers.

This module exposes a CloudflareAPI class that encapsulates credentials and a
requests.Session. Use cloudflare_api.from_env() to create a client from
environment variables (and a .env file if present).
"""
from __future__ import annotations

import os
from typing import Optional

import requests
from logger_config import configure_logger

logger = configure_logger("cloudflare")


class CloudflareAPIError(RuntimeError):
    """Raised for Cloudflare API related errors."""


class CloudflareAPI:
    def __init__(self, api_token: str, account_id: str, session: Optional[requests.Session] = None):
        if not api_token or not account_id:
            raise ValueError("Missing Cloudflare credentials")
        self.api_token = api_token
        self.account_id = account_id
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_token}"})

    def _api_call(self, method, endpoint: str, json: Optional[dict] = None):
        url = f"{self.base_url}/{endpoint}"
        try:
            resp = method(url, json=json, timeout=15)
            resp.raise_for_status()
            return resp.json().get("result", [])
        except requests.RequestException as exc:
            logger.error("Cloudflare API error: %s", exc)
            if getattr(exc, "response", None) is not None:
                logger.debug("Response body: %s", exc.response.text)
            raise CloudflareAPIError from exc

    def get_items_by_name(self, endpoint: str, name_prefix: str) -> tuple[list, list]:
        data = self._api_call(self.session.get, endpoint) or []
        filtered = [item for item in data if item.get("name", "").startswith(name_prefix)]
        return filtered, data

    def get_lists(self, name_prefix: str) -> tuple[list, list]:
        return self.get_items_by_name("lists", name_prefix)

    def get_policies(self, name_prefix: str) -> list:
        policies, _ = self.get_items_by_name("rules", name_prefix)
        return policies

    def create_list(self, name: str, domains: list[str]) -> dict:
        data = self._api_call(
            self.session.post,
            "lists",
            json={
                "name": name,
                "description": "Created by script.",
                "type": "DOMAIN",
                "items": [{"value": domain} for domain in domains],
            },
        )
        logger.debug("Created list %s", name)
        return data

    def delete_list(self, list_id: str, name: str) -> None:
        self._api_call(self.session.delete, f"lists/{list_id}")
        logger.debug("Deleted list %s", name)

    def delete_policy(self, name_prefix: str) -> None:
        policies = self.get_policies(name_prefix)

        if not policies:
            logger.info("No firewall policy %s found to delete", name_prefix)
            return
        elif len(policies) > 1:
            raise ValueError("More than one firewall policy found")

        self._api_call(self.session.delete, f"rules/{policies[0]['id']}")
        logger.info("Deleted policy %s", name_prefix)

    def create_policy(self, name: str, list_ids: list[str] | None = None, regex_tld: str | None = None) -> None:
        if list_ids:
            traffic = " or ".join([f"any(dns.domains[*] in ${list_id})" for list_id in list_ids])
            block_page_enabled = False
        else:
            traffic = f'any(dns.domains[*] matches "{regex_tld}")'
            block_page_enabled = True

        self._api_call(
            self.session.post,
            "rules",
            json={
                "name": name,
                "description": "Created by script.",
                "action": "block",
                "enabled": True,
                "filters": ["dns"],
                "traffic": traffic,
                "rule_settings": {"block_page_enabled": block_page_enabled},
            },
        )
        logger.info("Created firewall policy: %s", name)

    def create_policy_with_tlds(self, name: str, tld_list: list[str]) -> None:
        unique_tlds = sorted({tld for tld in tld_list or []})
        regex_tld = rf"[.](|{'|'.join(unique_tlds)})$"
        self.create_policy(name, regex_tld=regex_tld)

    def create_lists_and_policy(self, name_prefix: str, unique_domains: list[str], chunk_size: int = 1000) -> None:
        logger.info("Creating lists, please wait")
        list_ids = []

        for i, chunk in enumerate(self.chunk_list(unique_domains, chunk_size), 1):
            list_name = f"{name_prefix} {i}"
            created_list = self.create_list(list_name, chunk)
            list_ids.append(created_list["id"])

        self.create_policy(name_prefix, list_ids=list_ids)

    def delete_lists_and_policy(self, name_prefix: str, lists: list[dict]) -> None:
        self.delete_policy(name_prefix)
        logger.info("Deleting lists, please wait")
        for list_item in lists:
            self.delete_list(list_item["id"], list_item["name"])

    @staticmethod
    def chunk_list(items: list[str], chunk_size: int):
        for i in range(0, len(items), chunk_size):
            yield items[i : i + chunk_size]


# Factory to build a client from environment variables
def from_env() -> CloudflareAPI:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        # dotenv is optional at runtime; if absent env vars may still be set
        pass

    api_token = os.getenv("CF_API_TOKEN")
    account_id = os.getenv("CF_IDENTIFIER")
    return CloudflareAPI(api_token, account_id)
