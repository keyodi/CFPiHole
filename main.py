from typing import List, Set
from math import ceil
from logger_config import CustomFormatter
from pathlib import Path
import requests
import cloudflare_config
import configparser


class App:
    def __init__(self):
        # Configure logging
        self.logger = CustomFormatter.configure_logger("main")

    def run(self):
        """Fetches domains, creates lists, and manages firewall policies."""

        name_prefix = "[CFPihole] Block Ads"
        name_prefix_tld = "[CFPihole] Block TLDs"
        file_path_config = "config.ini"
        self.tldlist: Set[str] = set()

        # Ensure tmp directory exists
        tmp_dir = Path("./tmp")
        tmp_dir.mkdir(exist_ok=True)

        config = configparser.ConfigParser()
        try:
            config.read(file_path_config)
            if not config.sections():
                raise FileNotFoundError
        except FileNotFoundError:
            self.logger.error(
                f"Error: {file_path_config} does not exist or is empty, stopping"
            )
            return
        except configparser.DuplicateOptionError as e:
            self.logger.error(
                f"Error: Duplicate option '{e.option}' found in section '{e.section}' (Line {e.lineno})"
            )
            return

        all_domains = set()
        tld_files = [name for name in config["Lists"] if "tld" in name.lower()]
        other_files = [name for name in config["Lists"] if "tld" not in name.lower()]

        # Download all files first
        for domain_list in config["Lists"]:
            self.logger.debug(f"Setting list {domain_list}")
            self.download_file(config["Lists"][domain_list], domain_list)

        # Only one TLD list expected
        for tld_file in tld_files:
            self.tldlist = self.parse_tld_file(tld_file)
            break
        # Always block cn, ru, and xyz
        self.tldlist.update({"xyz", "cn", "ru"})

        # Parse other domain lists
        for domain_list in other_files:
            all_domains.update(self.convert_to_domain_list(domain_list))

        unique_domains = list(all_domains)
        total_new_lists = ceil(len(unique_domains) / 1000)

        self.logger.debug(
            f"Total not unique domains:{CustomFormatter.YELLOW} {len(all_domains)}"
        )
        self.logger.info(
            f"Total count of unique domains in list: {CustomFormatter.GREEN}{len(unique_domains)}"
        )
        self.logger.info(
            f"Total lists to create: {CustomFormatter.GREEN}{total_new_lists}"
        )

        # Check list size and limits
        cf_lists, total_cf_lists = cloudflare_config.get_block_lists(name_prefix)
        diff_cf_lists = len(total_cf_lists) - len(cf_lists)

        self.logger.debug(
            f"Number of CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
        )
        self.logger.debug(
            f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{diff_cf_lists}"
        )

        # Compare the lists size
        if len(unique_domains) == sum(l["count"] for l in cf_lists):
            self.logger.warning("Lists are the same size, stopping")
            return

        # Check total lists do not exceed 300
        elif (total_new_lists + diff_cf_lists) > 300:
            self.logger.warning(
                "Max of 300 lists allowed. Select smaller blocklists, stopping"
            )
            return

        # Create/Delete/Manage Cloudflare policies
        if self.tldlist:
            cloudflare_config.create_firewall_policy(name_prefix_tld, self.tldlist)
        else:
            cloudflare_config.delete_firewall_policy(name_prefix_tld)

        cloudflare_config.delete_lists_policy(name_prefix, cf_lists)
        cloudflare_config.create_lists_policy(name_prefix, unique_domains)

        self.logger.info(f"{CustomFormatter.GREEN}Done")

    def download_file(self, url, name, timeout=15):
        """Downloads a file from the given URL and saves it to the temporary directory."""

        self.logger.info(f"Downloading file from {url}")

        try:
            # Download the file and handle potential errors
            response = requests.get(url, allow_redirects=True, timeout=timeout)
            # Raise exception for non-200 status codes
            response.raise_for_status()
        except requests.Timeout:
            self.logger.error(f"Timeout occurred while downloading {url}")
            return
        except requests.RequestException as e:
            self.logger.error(f"Error downloading {url}: {e}")
            return

        # Save the downloaded content to the temporary directory
        file_path = Path("tmp") / name
        with file_path.open("wb") as file:
            file.write(response.content)

        self.logger.info(f"File size: {file_path.stat().st_size / (1024):.0f} KB")

    def parse_tld_file(self, filename) -> Set[str]:
        """Parse Adblock-formatted TLDs from the downloaded file in tmp/."""
        
        file_path = Path("tmp") / filename
        tlds = set()
        if not file_path.exists():
            self.logger.warning(f"Missing {file_path}, skipping")
            return tlds
        with file_path.open("r") as file:
            lines = file.readlines()
            for line in lines[1:]:
                line = line.strip()
                if not line or line.startswith(("!", "#", ";", "//")):
                    continue
                line = line.split("#")[0].split("//")[0].strip()
                if line.startswith("||"):
                    line = line[2:]
                if line.endswith("^"):
                    line = line[:-1]
                if line:
                    tlds.add(line)
        self.logger.info(
            f"Number of TLDs from remote list: {CustomFormatter.GREEN}{len(tlds)}"
        )
        return tlds

    def convert_to_domain_list(self, file_name: str) -> List[str]:
        """Converts a downloaded list or hosts file to a list of domains."""

        file_path = Path("tmp") / file_name

        with file_path.open("r") as file:
            data = file.readlines()

        # Check first 50 lines for hosts file indicator
        is_hosts_file = any(
            any(ip in line for ip in ["localhost ", "127.0.0.1 ", "::1 ", "0.0.0.0 "])
            for line in data[:50]
        )

        domains = []

        for line in data:
            # Skip comments and empty lines
            line = line.strip()
            if line.startswith(("#", ";")) or not line:
                continue

            if is_hosts_file:
                # Remove the IP address and the trailing newline
                parts = line.split()
                if len(parts) > 1:
                    domain = parts[1]
                    # Skip the localhost entry
                    if domain == "localhost":
                        continue
                else:
                    continue
            else:
                domain = line

            # Skip if TLD is not in the list
            if self.tldlist and domain.endswith(tuple(self.tldlist)):
                continue

            domains.append(domain)

        self.logger.info(f"Number of domains: {CustomFormatter.YELLOW}{len(domains)}")

        return domains


if __name__ == "__main__":
    app = App()
    app.run()
