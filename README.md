# CFPiHole

Simple Python script (runnable from GitHub Actions) that imports Pi-hole domain blocking lists into Cloudflare Zero-Trust Gateway configuration.

(based on https://github.com/IanDesuyo/CloudflareGatewayAdBlock)

## Requirements

- Python 3.8+
- pip packages: requests (the workflow installs needed deps)

## Usage

1. Create a Cloudflare API token: https://dash.cloudflare.com/profile/api-tokens. The token needs permissions to manage Zero Trust and firewall rules for the account. A minimal set used by this project is:
   - Account > Zero Trust : Edit
   - Account > Account Firewall Access Rules : Edit
   - Account > Access : Applications (if you manage Access apps)

2. Find your Account ID from the Cloudflare dashboard (for example: https://dash.cloudflare.com/?to=/:account/workers).
3. Clone this repository.
4. Configure GitHub Action secrets (in the repository settings):
   - `CF_IDENTIFIER` — your Cloudflare Account ID
   - `CF_API_TOKEN` — the API token created above
5. Edit `config.ini` with the blocking lists you want to import (format shown below).
6. Enable / run the GitHub Action (the workflow will pull the lists and update Cloudflare Zero-Trust Gateway rules).

## config.ini format

Create a `config.ini` in the repository root. At minimum provide one `[BlockLists]` entry or a `[TLDList]` entry. The sections and format are:

[BlockLists]
SomeName = https://example.com/blocklist.txt

[TLDList]
TLD = https://example.com/tlds.txt

- `[BlockLists]` is required unless you provide a `[TLDList]` section alone.
- Each `SomeName` is an arbitrary label for your list (used for logging/identification).
- URLs must point to plain text lists with one domain per line (typical Pi-hole format).

Example `config.ini`:

```ini
[BlockLists]
EasyList = https://easylist.to/easylist/easylist.txt
AdGuardDNS = https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt

[TLDList]
TLD = https://example.com/tlds.txt
```

Notes

- The script expects domain lists (one domain per line). It will normalize entries and skip invalid lines.
- If you only provide a `[TLDList]`, the script imports the TLD list entries instead of full domains.
- The repository's workflow uses the `config.ini` file in the default branch or the branch where the Action runs; ensure the config is present/updated in that branch.

If you'd like, I can also add a sample `config.ini` file to the repository or update the GitHub Action workflow to include an example run — tell me which branch to use if you want me to create files on a specific branch.
