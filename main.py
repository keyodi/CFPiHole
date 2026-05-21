from logger_config import CustomFormatter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
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
DOWNLOAD_WORKERS = 5
SKIP_PREFIXES = ("!", "#", ";", "//", "[")
COMMENT_CHARS = frozenset("#;")


class App:
    def __init__(self):
        # Configure logging
        self.logger = CustomFormatter.configure_logger("main")
        self.tld_list: set[str] = set()
        self.blocked_tld_suffixes: set[str] = set()
        self.session = None

    def _configure_session(self):
        """Configure requests session with connection pooling and retry strategy."""
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=requests.adapters.Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504]
            )
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

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
        tld_files, block_files = [], []
        
        # Separate TLD and block files
        for name in list_names:
            (tld_files if "tld" in name.lower() else block_files).append(name)

        # Check list size and limits BEFORE downloading (early exit)
        cf_lists, total_cf_lists = cloudflare_config.get_block_lists(NAME_PREFIX)
        diff_cf_lists = len(total_cf_lists) - len(cf_lists)

        self.logger.debug(
            f"Number of CFPiHole lists in Cloudflare: {CustomFormatter.YELLOW}{len(cf_lists)}"
        )
        self.logger.debug(
            f"Additional lists in Cloudflare: {CustomFormatter.YELLOW}{diff_cf_lists}"
        )

        # Download all files in parallel
        self._configure_session()
        try:
            self._download_files_parallel(config, list_names)
        finally:
            if self.session:
                self.session.close()

        # Parse all files in one pass
        all_domains = self.parse_all_files(tld_files, block_files)

        unique_domains = len(all_domains)
        total_new_lists = -(-unique_domains // LIST_CHUNK_SIZE)

        self.logger.info(
            f"Total count of unique domains in list: {CustomFormatter.GREEN}{unique_domains}"
        )
        self.logger.info(
            f"Total lists to create: {CustomFormatter.GREEN}{total_new_lists}"
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
        cloudflare_config.delete_firewall_policy(NAME_PREFIX_TLD)
        if self.tld_list:
            cloudflare_config.create_firewall_policy(
                NAME_PREFIX_TLD, sorted(self.tld_list)
            )

        cloudflare_config.delete_lists_policy(NAME_PREFIX, cf_lists)
        cloudflare_config.create_lists_policy(NAME_PREFIX, sorted(all_domains))

        self.logger.info(f"{CustomFormatter.GREEN}Done")

    def _download_files_parallel(self, config, list_names):
        """Download all files in parallel using ThreadPoolExecutor."""
        download_map = {domain_list: config["Lists"][domain_list] for domain_list in list_names}
        
        with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
            futures = {
                executor.submit(self.download_file, url, name): (name, url)
                for name, url in download_map.items()
            }
            
            # Process completed downloads
            for future in as_completed(futures):
                name, url = futures[future]
                try:
                    file_size_kb = future.result()
                    if file_size_kb is not None:
                        self.logger.info(f"Downloading file from {url}")
                        self.logger.info(f"File size: {CustomFormatter.GREEN}{file_size_kb:.0f} KB")
                except Exception as e:
                    self.logger.error(f"Failed to download {name}: {e}")

    def download_file(self, url, name):
        """Downloads a file from the given URL and saves it to the temporary directory."""
        try:
            response = self.session.get(url, allow_redirects=True, timeout=TIMEOUT)
            response.raise_for_status()
            file_path = TMP_DIR_PATH / name
            file_path.write_bytes(response.content)
            file_size_kb = file_path.stat().st_size / 1024
            
            return file_size_kb
        except requests.RequestException as e:
            self.logger.error(f"Error downloading {url}: {e}")
            return None

    def parse_all_files(self, tld_files, block_files) -> set[str]:
        """Parse TLD and domain lists in one pass through files."""

        self.tld_list = set()
        all_domains: set[str] = set()

        # Parse TLD file if present
        if tld_files:
            self.tld_list = self.parse_tld_file(tld_files[0])
            self.blocked_tld_suffixes = {f".{tld}" for tld in self.tld_list}

        # Parse domain block lists
        for domain_list in block_files:
            all_domains |= self.convert_to_domain_list(domain_list)

        return all_domains

    def parse_tld_file(self, filename) -> set[str]:
        """Parse Adblock-formatted TLDs from the downloaded file in tmp/."""

        file_path = TMP_DIR_PATH / filename

        if not file_path.exists():
            self.logger.warning(f"Missing {file_path}, skipping")
            return set()

        try:
            # Read entire file at once for better performance
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            
            # Use set comprehension for efficiency
            tlds = {
                line.removeprefix("||").removesuffix("^")
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith(SKIP_PREFIXES)
            }

            self.logger.info(
                f"Number of TLDs from remote list: {CustomFormatter.GREEN}{len(tlds)}"
            )
            return tlds
        except Exception as e:
            self.logger.error(f"Error parsing TLD file {filename}: {e}")
            return set()

    def convert_to_domain_list(self, file_name: str) -> set[str]:
        """Converts a downloaded list or hosts file to a set of domains."""

        file_path = TMP_DIR_PATH / file_name

        if not file_path.exists():
            self.logger.warning(f"Missing {file_path}, skipping")
            return set()

        try:
            # Read entire file at once for better performance
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            domains: set[str] = set()
            is_hosts_file = None  # None = undetermined

            for line in content.splitlines():
                line = line.strip()
                
                # Skip empty lines and comments faster
                if not line or line[0] in COMMENT_CHARS:
                    continue

                # Detect file format on first data line
                if is_hosts_file is None:
                    is_hosts_file = "127.0.0.1 " in line or "0.0.0.0 " in line

                # Extract domain
                parts = line.split()
                if not parts:
                    continue

                domain = (
                    (parts[1] if is_hosts_file and len(parts) > 1 else parts[0])
                    .lower()
                    .rstrip(".")
                )

                if is_hosts_file and "localhost" in domain:
                    continue

                # Use generator with any() for early exit on match
                if self.blocked_tld_suffixes and any(
                    domain.endswith(suffix) for suffix in self.blocked_tld_suffixes
                ):
                    continue

                domains.add(domain)

            self.logger.debug(
                f"{file_name} - Number of domains: {CustomFormatter.YELLOW}{len(domains)}"
            )
            return domains
        except Exception as e:
            self.logger.error(f"Error parsing domain file {file_name}: {e}")
            return set()


if __name__ == "__main__":
    App().run()
