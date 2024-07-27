import logging
import pathlib
from typing import List
import requests
import cloudflare
import configparser
import pandas as pd
import os
import time


class App:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("main")

        # Define file paths
        self.file_path_whitelist = "whitelist.txt"
        self.file_path_tld = "tldlist.txt"
        self.file_path_config = "config.ini"

        self.name_prefix = f"[CFPihole]"
        self.whitelist = self.loadWhitelist()
        self.tldlist = self.loadTldlist()

    def loadWhitelist(self):

        if os.path.exists(self.file_path_whitelist):
            return open(self.file_path_whitelist, "r").read().split("\n")

        else:
            self.logger.warning(
                f"\033[0;31;97m Missing {self.file_path_whitelist}, skipping\033[0;0m"
            )
            return

    def loadTldlist(self):

        if os.path.exists(self.file_path_tld):
            return open(self.file_path_tld, "r").read().split("\n")

        else:
            self.logger.warning(
                f"\033[0;31;97m Missing {self.file_path_tld}, skipping\033[0;0m"
            )
            return

    def run(self):
        # check tmp dir exists
        try:
            os.makedirs("./tmp", exist_ok=True)
        except OSError as error:
            self.logger.error(f"\033[0;31;40m Unable to create tmp folder\033[0;0m")

        if os.path.exists(self.file_path_config):
            config = configparser.ConfigParser()
            config.read(self.file_path_config)

            all_domains = []
            for list in config["Lists"]:
                print("Setting list " + list)

                self.download_file(config["Lists"][list], list)
                domains = self.convert_to_domain_list(list)
                all_domains = all_domains + domains

            unique_domains = pd.Series(all_domains).unique()
            total_new_lists = round(len(unique_domains) / 1000)

            self.logger.info(
                f"Total count of unique domains in list: {len(unique_domains)}"
            )
            self.logger.info(f"Total lists to create: {total_new_lists}")

            # check if the list is already in Cloudflare
            cf_lists = cloudflare.get_lists(self.name_prefix)

            # get total lists is already in Cloudflare
            total_cf_lists = cloudflare.get_total_lists()

            # additional lists created outside of CFPihole
            diff_cf_lists = len(total_cf_lists) - len(cf_lists)

            self.logger.info(f"Number of CFPiHole lists in Cloudflare: {len(cf_lists)}")

            self.logger.info(f"Additional lists in Cloudflare: {diff_cf_lists}")

            # compare the lists size
            if len(unique_domains) == sum([l["count"] for l in cf_lists]):
                self.logger.warning(
                    f"\033[0;33m Lists are the same size, stopping\033[0;0m"
                )

            # check total lists do not exceed 300
            elif (total_new_lists + diff_cf_lists) > 300:
                self.logger.warning(
                    f"\033[0;33m Max of 300 lists allowed. Select smaller blocklists, stopping\033[0;0m"
                )

            else:
                # delete the policy
                cf_policies = cloudflare.get_firewall_policies(self.name_prefix)
                if len(cf_policies) > 0:
                    cloudflare.delete_firewall_policy(cf_policies[0]["id"])

                self.logger.info("Deleting lists, please wait")

                # delete the lists
                for l in cf_lists:
                    self.logger.debug(f"Deleting list {l['name']}")

                    # sleep to prevent rate limit
                    #time.sleep(0.8)

                    cloudflare.delete_list(l["id"])

                cf_lists = []

                self.logger.info("Creating lists, please wait")

                # chunk the domains into lists of 1000 and create them
                for chunk in self.chunk_list(unique_domains, 1000):
                    list_name = f"{self.name_prefix} {len(cf_lists) + 1}"

                    self.logger.debug(f"Creating list {list_name}")

                    _list = cloudflare.create_list(list_name, chunk)

                    # sleep to prevent rate limit
                    #time.sleep(0.8)

                    cf_lists.append(_list)

                # get the gateway policies
                cf_policies = cloudflare.get_firewall_policies(self.name_prefix)

                self.logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")

                # setup the gateway policy
                if len(cf_policies) == 0:
                    self.logger.info("Creating firewall policy")

                    cf_policies = cloudflare.create_gateway_policy(
                        f"{self.name_prefix} Block Ads", [l["id"] for l in cf_lists]
                    )

                elif len(cf_policies) != 1:
                    self.logger.error("More than one firewall policy found")

                    raise Exception("More than one firewall policy found")

                else:
                    self.logger.info("Updating firewall policy")

                    cloudflare.update_gateway_policy(
                        f"{self.name_prefix} Block Ads",
                        cf_policies[0]["id"],
                        [l["id"] for l in cf_lists],
                  )

                self.logger.info("Done")

        else:
            self.logger.error(
                f"\033[0;31;40m {self.file_path_config} does not exist, stopping\033[0;0m"
            )

    def is_valid_hostname(self, hostname):
        import re

        if len(hostname) > 255:
            return False
        hostname = hostname.rstrip(".")
        allowed = re.compile(r"^[a-z0-9]([a-z0-9\-\_]{0,61}[a-z0-9])?$", re.IGNORECASE)
        labels = hostname.split(".")

        # the TLD must not be all-numeric
        if re.match(r"^[0-9]+$", labels[-1]):
            return False

        return all(allowed.match(x) for x in labels)

    def download_file(self, url, name):
        self.logger.info(f"Downloading file from {url}")

        r = requests.get(url, allow_redirects=True)

        path = pathlib.Path("tmp/" + name)
        open(path, "wb").write(r.content)

        self.logger.info(f"File size: {path.stat().st_size}")

    def convert_to_domain_list(self, file_name: str):
        with open("tmp/" + file_name, "r") as f:
            data = f.read()

        # TODO: temp fix to account for hosts or domains contained in each iteration
        # check if the file is a hosts file or a list of domain
        is_hosts_file = False
        for ip in ["localhost ", "127.0.0.1 ", "::1 ", "0.0.0.0 "]:
            if ip in data:
                is_hosts_file = True
                break

        domains = []

        for line in data.splitlines():
            # skip comments and empty lines
            if (
                line.startswith("#")
                or line.startswith(";")
                or line == "\n"
                or line == ""
            ):
                continue

            # skip tld is in List
            if not line.endswith(tuple(self.tldlist)):
                continue

            if is_hosts_file:
                # remove the ip address and the trailing newline
                domain = line.split()[1].rstrip()

                # skip the localhost entry
                if domain == "localhost":
                    continue

            else:
                domain = line.rstrip()

            # check whitelist
            if domain in self.whitelist:
                continue

            domains.append(domain)

        self.logger.info(f"Number of domains: {len(domains)}")

        return domains

    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]


if __name__ == "__main__":
    app = App()
    app.run()
