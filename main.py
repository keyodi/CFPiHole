from typing import List
from math import ceil
from logger_config import CustomFormatter
import os
import requests
import cloudflare_config
import configparser


class App:
    def __init__(self):
        # Configure logging
        self.logger = CustomFormatter.configure_logger("main")

        self.whitelist = self._load_file("whitelist.txt")
        self.tldlist = self._load_file("tldlist.txt")

    def _load_file(self, filename):
        name_prefix_tld = "[CFPihole] Block TLDs"

        if os.path.exists(filename):
            with open(filename, "r") as file:
                data = [line.strip() for line in file.readlines() if line.strip()]

            if data and "tldlist" in filename:
                # Setup TLD gateway policy
                cloudflare_config.create_firewall_policy(name_prefix_tld, data)

            if not data and "tldlist" in filename:
                # Delete TLD gateway policy if file is empty
                cloudflare_config.delete_firewall_policy(name_prefix_tld)

                return []

            return data

        else:
            self.logger.warning(f"Missing {filename}, skipping")

            return []

    def run(self):
        """Fetches domains, creates lists, and manages firewall policies."""
        name_prefix = "[CFPihole] Block Ads"
        file_path_config = "config.ini"

        # Ensure tmp directory exists
        os.makedirs("./tmp", exist_ok=True)

        if os.path.exists(file_path_config):
            config = configparser.ConfigParser()
            config.read(file_path_config)

            all_domains = []
            for domain_list in config["Lists"]:
                self.logger.debug(f"Setting list {domain_list}")

                self.download_file(config["Lists"][domain_list], domain_list)
                domains = self.convert_to_domain_list(domain_list)
                all_domains.extend(domains)

            unique_domains = list(set(all_domains))
            total_new_lists = ceil(len(unique_domains) / 1000)

            self.logger.debug(
                f"Total not unique domains:{CustomFormatter.YELLOW} {len(all_domains)}"
            )
            self.logger.info(
                f"Total count of unique domains in list: {CustomFormatter.GREEN}{(len(unique_domains))}"
            )
            self.logger.info(
                f"Total lists to create: {CustomFormatter.GREEN}{total_new_lists}"
            )

            # Check list size and limits
            cf_lists, total_cf_lists = cloudflare_config.get_firewall_polcy(name_prefix)

            diff_cf_lists = len(total_cf_lists) - len(cf_lists)

            self.logger.debug(
                f"Number of CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
            )
            self.logger.debug(
                f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{diff_cf_lists}"
            )

            # Compare the lists size
            if len(unique_domains) == sum([l["count"] for l in cf_lists]):
                self.logger.warning("Lists are the same size, stopping")
                return []

            # Check total lists do not exceed 300
            elif (total_new_lists + diff_cf_lists) > 300:
                self.logger.warning(
                    "Max of 300 lists allowed. Select smaller blocklists, stopping"
                )
                return []

        else:
            self.logger.error(f"{file_path_config} does not exist, stopping")
            return []

        # Create/Delete/Manage Cloudflare policies
        cloudflare_config.delete_lists_policy(name_prefix, cf_lists)
        cloudflare_config.create_lists_policy(name_prefix, unique_domains)

        self.logger.info(f"{CustomFormatter.GREEN}Done")

    def download_file(self, url, name):
        """Downloads a file from the given URL and saves it to the temporary directory.

        Args:
            url: URL of the file to download.
            name: Name to use for the downloaded file.

        Returns:
            str: Path to the downloaded file.
        """

        self.logger.info(f"Downloading file from {url}")

        # Download the file and handle potential errors
        response = requests.get(url, allow_redirects=True)
        # Raise exception for non-200 status codes
        response.raise_for_status()

        # Save the downloaded content to the temporary directory
        file_path = os.path.join("tmp", name)
        with open(file_path, "wb") as file:
            file.write(response.content)

        self.logger.info(f"File size: {os.path.getsize(file_path) / (1024):.0f} KB")

    def convert_to_domain_list(self, file_name: str):
        """Converts a downloaded list or hosts file to a list of domains.

        Args:
            file_name: Name of the downloaded list file.

        Returns:
            list: List of extracted domains from the file.
        """

        # Combine path elements
        file_path = os.path.join("tmp", file_name)

        with open(file_path, "r") as file:
            data = file.read()

        # Check if the file is a hosts file or a list of domains
        is_hosts_file = any(
            ip in data for ip in ["localhost ", "127.0.0.1 ", "::1 ", "0.0.0.0 "]
        )

        domains = []

        for line in data.splitlines():
            # Skip comments and empty lines
            if line.startswith(("#", ";")) or not line.strip():
                continue

            # Skip if TLD is not in the list
            if self.tldlist and not line.endswith(tuple(self.tldlist)):
                continue

            if is_hosts_file:
                # Remove the IP address and the trailing newline
                parts = line.split()
                if len(parts) > 1:
                    domain = parts[1].rstrip()
                    # Skip the localhost entry
                    if domain == "localhost":
                        continue
                else:
                    continue

            else:
                domain = line.rstrip()

            # Check whitelist
            if domain in self.whitelist:
                continue

            domains.append(domain)

        self.logger.info(f"Number of domains: {CustomFormatter.YELLOW}{len(domains)}")

        return domains


if __name__ == "__main__":
    app = App()
    app.run()
