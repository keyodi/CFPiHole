from logger_config import CustomFormatter
import cloudflare


# configure logging
logger = CustomFormatter.configure_logger("tld")

# define variables
name_prefix = f"[CFPihole] Block TLDs"


def create_tld_policy(tld_list: list):
    """Creates or updates a TLD blocking policy in Cloudflare."""

    # Get existing policies
    cf_policies = cloudflare.get_firewall_policies(name_prefix)

    if cf_policies:
        policy_id = cf_policies[0]["id"]
        num_policies = len(cf_policies)

    else:
        num_policies = 0
        policy_id = None

    # Remove duplicates, sort, and create regex
    unique_tlds = sorted(set(tld.replace(".", "") for tld in tld_list))
    regex_tld = rf"[.](|{"|".join(unique_tlds)})$"

    if num_policies == 0:
        logger.info("Creating firewall TLD policy")
        cloudflare.create_gateway_policy_tld(name_prefix, regex_tld)

    elif num_policies == 1:
        logger.info("Updating firewall policy")
        cloudflare.update_gateway_policy_tld(name_prefix, policy_id, regex_tld)

    else:
        logger.error("More than one firewall policy found")
        raise Exception("More than one firewall policy found")

    logger.info("Created/Updated TLD firewall policy")


def delete_tld_policy():
    """Deletes the TLD blocking policy in Cloudflare."""

    # Get existing policies
    cf_policies = cloudflare.get_firewall_policies(name_prefix)

    if cf_policies:
        cloudflare.delete_firewall_policy(cf_policies[0]["id"])
        logger.info("Deleted TLD firewall policy")

    else:
        logger.info("No TLD firewall policy found to delete")
