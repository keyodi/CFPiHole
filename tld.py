from logger_config import CustomFormatter
import cloudflare


# configure logging
logger = CustomFormatter.configure_logger("tld")

# define variables
name_prefix = f"[CFPihole] Block TLDs"


def create_tld_policy(tld_list: list):
    # delete the policy
    cf_policies = cloudflare.get_firewall_policies(name_prefix)

    if len(cf_policies) > 0:
        cloudflare.delete_firewall_policy(cf_policies[0]["id"])

    # get the gateway policies
    cf_policies = cloudflare.get_firewall_policies(name_prefix)

    logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")

    # remove dups and sort
    tld_list = sorted(tld_list)
    tld_list = "".join([str(elem.strip()) for elem in tld_list])
    regex_tld = "[.](" + tld_list.replace(".", "|").lstrip("|").replace("\n", "") + ")$"

    # setup the gateway policy
    if len(cf_policies) == 0:
        logger.info("Creating firewall TLD policy")

        cf_policies = cloudflare.create_gateway_policy_tld(f"{name_prefix}", regex_tld)

    elif len(cf_policies) != 1:
        logger.error("More than one firewall policy found")

        raise Exception("More than one firewall policy found")

    else:
        logger.info("Updating firewall policy")

        cloudflare.update_gateway_policy_tld(
            f"{name_prefix}", cf_policies[0]["id"], regex_tld
        )

    logger.info("Created TLD firewall policy")


def delete_tld_policy():
    # delete the policy
    cf_policies = cloudflare.get_firewall_policies(name_prefix)

    if len(cf_policies) > 0:
        cloudflare.delete_firewall_policy(cf_policies[0]["id"])

    logger.info("Deleted TLD firewall policy")
