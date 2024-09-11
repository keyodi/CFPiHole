from typing import List
from math import ceil
from logger_config import CustomFormatter
import os
import requests
import cloudflare
import tld
import configparser
import time


class App:
    def __init__(self):
        # Configure logging
        self.logger = CustomFormatter.configure_logger("main")

        self.whitelist = self.load_whitelist()
        self.tldlist = self.load_tldlist()

    def load_whitelist(self):
        # Define static file path
        file_path_whitelist = "whitelist.txt"

        # Read list of domains to exclude from lists
        if os.path.exists(file_path_whitelist):
            with open(file_path_whitelist, "r") as file:
                return file.read().splitlines()

        else:
            self.logger.warning(f"Missing {file_path_whitelist}, skipping")
            return []

    def load_tldlist(self):
        """Loads the list of TLDs from a file.

        Returns:
        list: List of TLD strings, or an empty list if the file is missing or empty.
        """

        file_path_tld = "tldlist.txt"

        # Read list of tld domains
        if os.path.exists(file_path_tld):
            with open(file_path_tld, "r") as file:
                tld_list = file.readlines()
            # Remove empty lines and check if file is empty
            tld_list = [line.strip() for line in tld_list if line.strip()]
            if tld_list:
                return tld_list
            else:
                tld.delete_tld_policy()
                return []

        else:
            self.logger.warning(f"Missing {file_path_tld}, skipping")
            return []

    def run(self):
        # Define static variables
        name_prefix = f"[CFPihole] Block Ads"
        file_path_config = "config.ini"

        # Ensure tmp directory exists
        os.makedirs("./tmp", exist_ok=True)

        if os.path.exists(file_path_config):
            config = configparser.ConfigParser()
            config.read(file_path_config)

            all_domains = []
            for domain_list in config["Lists"]:
                self.logger.debug(f"Setting list " + domain_list)

                self.download_file(config["Lists"][domain_list], domain_list)
                domains = self.convert_to_domain_list(domain_list)
                all_domains.extend(domains)

            self.logger.debug(
                f"Total not unique domains:{CustomFormatter.YELLOW} {len(all_domains)}"
            )

            unique_domains = list(set(all_domains))
            total_new_lists = ceil(len(unique_domains) / 1000)

            self.logger.info(
                f"Total count of unique domains in list: {CustomFormatter.GREEN}{(len(unique_domains))}"
            )
            self.logger.info(
                f"Total lists to create: {CustomFormatter.GREEN}{total_new_lists}"
            )

            # Count of lists in Cloudflare
            cf_lists, total_cf_lists = cloudflare.get_lists(name_prefix)

            # Additional lists created outside of CFPihole
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

            # Check total lists do not exceed 300
            elif (total_new_lists + diff_cf_lists) > 300:
                self.logger.warning(
                    "Max of 300 lists allowed. Select smaller blocklists, stopping"
                )

            else:
                # Delete the policy
                cf_policies = cloudflare.get_firewall_policies(name_prefix)
                if len(cf_policies) > 0:
                    cloudflare.delete_firewall_policy(cf_policies[0]["id"])

                # delete the lists
                for l in cf_lists:
                    self.logger.info(f"Deleting list {l['name']}")

                    cloudflare.delete_list(l["id"])

                    # Sleep to prevent rate limit
                    time.sleep(0.75)

                cf_lists = []

                # Sleep to prevent rate limit
                self.logger.warning(
                    "Pausing for 60 seconds to prevent rate limit, please wait"
                )
                time.sleep(60)

                self.logger.info("Creating lists, please wait")

                # Chunk the domains into lists of 1000 and create them
                for chunk in self.chunk_list(unique_domains, 1000):
                    list_name = f"{name_prefix} {len(cf_lists) + 1}"

                    self.logger.debug(f"Creating list {list_name}")

                    _list = cloudflare.create_list(list_name, chunk)

                    cf_lists.append(_list)

                    # sleep to prevent rate limit
                    time.sleep(0.75)

                # Setup TLD gateway policy
                tld.create_tld_policy(self.tldlist)

                # Get the gateway policies
                cf_policies = cloudflare.get_firewall_policies(name_prefix)

                self.logger.info(
                    f"Number of policies in Cloudflare: {len(cf_policies)}"
                )

                # Setup the gateway policy
                if len(cf_policies) == 0:
                    self.logger.info("Creating firewall policy")

                    cf_policies = cloudflare.create_gateway_policy(
                        f"{name_prefix}", [l["id"] for l in cf_lists]
                    )

                elif len(cf_policies) != 1:
                    self.logger.error("More than one firewall policy found")

                    raise Exception("More than one firewall policy found")

                else:
                    self.logger.info("Updating firewall policy")

                    cloudflare.update_gateway_policy(
                        f"{name_prefix}",
                        cf_policies[0]["id"],
                        [l["id"] for l in cf_lists],
                    )

                self.logger.info(f"{CustomFormatter.GREEN} Done")

        else:
            self.logger.error(f"{file_path_config} does not exist, stopping")

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

    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]


if __name__ == "__main__":
    app = App()
    app.run()
