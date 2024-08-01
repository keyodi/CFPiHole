import os
import logging
import cloudflare
import configparser


class App:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("main")

        # Define file paths
        self.file_path_tld = "tldlist.txt"
        self.name_prefix = f"[CFPihole] Block TLDs"
        self.tldlist = self.load_tldlist()

    def load_tldlist(self):
        # read list of tld domains
        with open(self.file_path_tld, "r") as file:
            return file.read()

    def run(self):
        # delete the policy
        cf_policies = cloudflare.get_firewall_policies(self.name_prefix)

        if len(cf_policies) > 0:
            cloudflare.delete_firewall_policy(cf_policies[0]["id"])

        if len(self.tldlist) != 0:
            # get the gateway policies
            cf_policies = cloudflare.get_firewall_policies(self.name_prefix)

            self.logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")

            regex_tld = (
                "[.]("
                + self.tldlist.replace(".", "|").lstrip("|").replace("\n", "")
                + ")$"
            )

            # setup the gateway policy
            if len(cf_policies) == 0:
                self.logger.info("Creating firewall policy")

                cf_policies = cloudflare.create_gateway_policy_tld(
                    f"{self.name_prefix}", regex_tld
                )

            elif len(cf_policies) != 1:
                self.logger.error("More than one firewall policy found")

                raise Exception("More than one firewall policy found")

            else:
                self.logger.info("Updating firewall policy")

                cloudflare.update_gateway_policy_tld(
                    f"{self.name_prefix}", cf_policies[0]["id"], regex_tld
                )

            self.logger.info(f"\033[92m Done\033[0;0m")

        else:
            self.logger.info(f"\033[92m tldlist.txt is empty\033[0;0m")


if __name__ == "__main__":
    app = App()
    app.run()

