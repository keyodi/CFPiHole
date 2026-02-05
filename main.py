from logger_config import CustomFormatter
from pathlib import Path
import requests
import cloudflare_config
import configparser


# Constants
NAME_PREFIX = "[CFPihole] Block Ads"
NAME_PREFIX_TLD = "[CFPihole] Block TLDs"
FILE_PATH_CONFIG = "config.ini"
TMP_DIR_PATH = Path("./tmp")
TIMEOUT = 15
MAX_LISTS_ALLOWED = 300
LIST_CHUNK_SIZE = 1000

class App:
    def __init__(self):
        # Configure logging
        self.logger = CustomFormatter.configure_logger("main")
        self.tld_list: set[str] = set()

    def run(self):
        """Fetches domains, creates lists, and manages firewall policies."""

        # Ensure tmp directory exists
        TMP_DIR_PATH.mkdir(exist_ok=True)

        config = configparser.ConfigParser()
        config.read(FILE_PATH_CONFIG)
        
        # Check if the file was loaded and has the required 'Lists' section
        if not config.has_section("Lists"):
            self.logger.error(
                f"Error: {FILE_PATH_CONFIG} is missing the [Lists] section, file doesn't exist or duplicate values."
            )
            return

        list_names = config.options("Lists")
        tld_files = [name for name in list_names if "tld" in name.lower()]
        block_files = [name for name in list_names if "tld" not in name.lower()]

        # Download all files first
        with requests.Session() as session:
            for domain_list in list_names:
                self.logger.debug(f"Setting list {domain_list}")
                self.download_file(session, config["Lists"][domain_list], domain_list)

       # Only one TLD list expected
        if tld_files:
            self.tld_list = tuple(self.parse_tld_file(tld_files[0])) 
        else:
            self.tld_list = ()

        # Parse other domain lists
        all_domains: set[str] = set()
        for domain_list in block_files:
            all_domains |= self.convert_to_domain_list(domain_list)

        unique_domains = len(all_domains)
        total_new_lists = -(-unique_domains // LIST_CHUNK_SIZE)

        self.logger.info(
            f"Total count of unique domains in list: {CustomFormatter.GREEN}{unique_domains}"
        )
        self.logger.info(
            f"Total lists to create: {CustomFormatter.GREEN}{total_new_lists}"
        )

        # Check list size and limits
        cf_lists, total_cf_lists = cloudflare_config.get_block_lists(NAME_PREFIX)
        diff_cf_lists = len(total_cf_lists) - len(cf_lists)

        self.logger.debug(
            f"Number of CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
        )
        self.logger.debug(
            f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{diff_cf_lists}"
        )

        # Compare the lists size
        if unique_domains == sum(l["count"] for l in cf_lists):
            self.logger.warning("Lists are the same size, stopping")
            return

        # Check total lists do not exceed limit
        if (total_new_lists + diff_cf_lists) > MAX_LISTS_ALLOWED:
            self.logger.warning(
                f"Max of {MAX_LISTS_ALLOWED} lists allowed. Select smaller blocklists, stopping"
            )
            return

        # Create/Delete/Manage Cloudflare policies
        if self.tld_list:
            cloudflare_config.create_firewall_policy(NAME_PREFIX_TLD, sorted(self.tld_list))
        else:
            cloudflare_config.delete_firewall_policy(NAME_PREFIX_TLD)

        cloudflare_config.delete_lists_policy(NAME_PREFIX, cf_lists)
        cloudflare_config.create_lists_policy(NAME_PREFIX, sorted(all_domains))

        self.logger.info(f"{CustomFormatter.GREEN}Done")

    def download_file(self, session, url, name):
        """Downloads a file from the given URL and saves it to the temporary directory."""

        self.logger.info(f"Downloading file from {url}")

        try:
            response = session.get(url, allow_redirects=True, timeout=TIMEOUT)
            response.raise_for_status()
            file_path = TMP_DIR_PATH / name
            file_path.write_bytes(response.content)
            self.logger.info(f"File size: {file_path.stat().st_size / 1024:.0f} KB")
        except requests.RequestException as e:
            self.logger.error(f"Error downloading {url}: {e}")

    def parse_tld_file(self, filename) -> set[str]:
        """Parse Adblock-formatted TLDs from the downloaded file in tmp/."""

        file_path = TMP_DIR_PATH / filename
        tlds: set[str] = set()

        if not file_path.exists():
            self.logger.warning(f"Missing {file_path}, skipping")
            return tlds

        with file_path.open("r") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith(("!", "#", ";", "//", "[")):
                    continue

                line = line.split("#")[0].split("//")[0].strip()
                line = line.removeprefix("||").removesuffix("^")

                if line:
                    tlds.add(line)

        self.logger.info(
            f"Number of TLDs from remote list: {CustomFormatter.GREEN}{len(tlds)}"
        )
        return tlds

    def convert_to_domain_list(self, file_name: str) -> set[str]:
        """Converts a downloaded list or hosts file to a set of domains."""

        file_path = TMP_DIR_PATH / file_name

        with file_path.open("r") as file:
            data = file.readlines()

        # Check first 50 lines for hosts file indicator
        is_hosts_file = any(
            ip in line for line in data[:50] for ip in ["127.0.0.1 ", "0.0.0.0 "]
        )

        domains = set[str] = set()

        for line in data:
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
        
            domain = (line.split()[1] if is_hosts_file and len(line.split()) > 1 else line).lower().rstrip(".")
        
            if is_hosts_file and "localhost" in domain:
                continue

            domain_parts = domain.split('.')
            if domain_parts and domain_parts[-1] in self.tld_list:
                continue

            domains.add(domain)

        self.logger.debug(
            f"{file_name} - Number of domains: {CustomFormatter.YELLOW}{len(domains)}"
        )
        return domains

if __name__ == "__main__":
    App().run()
