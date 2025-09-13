## Intro

**NetScope** is a compact, single-file CLI tool (`netscope.py`) that collects passive internet-scale metadata about ASNs, IPs and ISP organizations and presents it as a human-friendly terminal report or machine-friendly JSON. It’s designed for network engineers, incident responders, threat analysts and researchers who need a quick, repeatable way to profile networks.

---

## What you can see with NetScope

When you run NetScope you will get:

* **ASN & Organization** — ASN (e.g. `AS15169`) + organization name.
* **Announced prefixes** — IPv4/IPv6 blocks announced by the ASN.
* **Geo samples** — representative IPs sampled from prefixes with `country/region/city/lat/lon/isp/org`.
* **Peering / Network info** — peers / upstreams / customers counts (merged from BGPView + RIPEstat).
* **Contacts** — RDAP/RIPEstat technical & abuse contacts (emails / phones where available).
* **Active analysis (optional)** — ping RTT and traceroute hops (enabled only with `--active`).
* **ASCII charts** — terminal histograms (prefix distribution by country, peering diversity bars).
* **Detected ISP company** — best-effort canonical ISP name for an IP or ASN.
* **Warnings & safety notes** — what was passive vs active, and sampling limits.

Outputs: pretty terminal report or JSON export for automation.

---

## Why I made NetScope

* Reduce friction: one command that replaces several manual API lookups.
* Safe-by-default: passive lookups only; active probing is explicitly opt-in.
* One-file, easy to audit and include in scripts or pipelines.
* Useful for troubleshooting, abuse reporting, threat triage, and topology research.

---

## How I made NetScope (brief)

* **Language:** Python 3 (single-file CLI).
* **Public data sources:** BGPView (ASN/prefixes), RIPEstat (AS overview & relations), PeeringDB (peering hints), RDAP (contacts), ip-api (IP geolocation).
* **Optional enrichments:** `ipwhois` and `netaddr` for additional WHOIS/prefix parsing if installed.
* **Design choices:** caching (`~/.netscope_cache.json`), rate controls for geolocation, passive-first approach, clear warnings.

---

## Installation (Linux & macOS — professional and reproducible)

**Recommended:** use a virtual environment.

### 1) One-liner (bash / zsh) — Linux & macOS

This creates a venv, activates it, and installs core requirements:

```bash
python3 -m venv venv && source venv/bin/activate && pip install requests python-dotenv ipwhois netaddr
```

* Works on common Linux distributions and macOS with `bash`/`zsh`.
* If you use `fish` shell:

  ```bash
  python3 -m venv venv && source venv/bin/activate.fish && pip install requests python-dotenv ipwhois netaddr
  ```

### 2) Step-by-step (if you prefer)

```bash
# create & activate venv
python3 -m venv venv
source venv/bin/activate

# install required packages
pip install requests

# optional/recommended extras (better WHOIS & prefix handling + dotenv)
pip install python-dotenv ipwhois netaddr
```

### 3) Using a requirements file

Create `requirements.txt`:

```
requests
python-dotenv
ipwhois
netaddr
```

Then:

```bash
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

---

## Environment variables (`.env`) — required for full functionality

NetScope will use environment variables for optional API keys and feature flags. Some APIs work without keys, but **for reliable, full functionality you should provide settings in a `.env` file** (placed beside `netscope.py`) or export them into your shell.

Create a `.env` file (example):

```text
# .env (example)
# Optional API keys (put your keys if you have them)
BGPVIEW_API_KEY=your_bgpview_key_here
PEERINGDB_API_KEY=your_peeringdb_key_here

# Optional toggles
IPWHOIS_ENABLED=true
```

**How to load `.env` into your shell (bash / zsh):**

Option A — export variables into current shell:

```bash
# simple, portable
set -o allexport
source .env
set +o allexport
```

Option B — use `python-dotenv` to run the tool with .env loaded (no need to export):

```bash
# after installing python-dotenv
dotenv run -- python netscope.py --query "8.8.8.8"
```

> **Important:** If you don’t load `.env` (or export needed variables), some API-dependent features may return limited/no data. Loading `.env` is the recommended approach for full, reproducible behavior.

---

## How to run NetScope

Place `netscope.py` in your working directory (and `.env` if used). Example commands:

### Basic queries

```bash
# ASN
python netscope.py --query "AS3356"

# Single IP
python netscope.py --query "8.8.8.8"

# Organization / ISP name
python netscope.py --query "level3"
```

### Check your public IP then query it

```bash
# get public IP
curl ifconfig.me

# use the returned IP with NetScope
python netscope.py --query "YOUR_PUBLIC_IP"
# example
python netscope.py --query "203.0.113.5"
```

> This gives an approximation of where your ISP’s public IP exits are located — not your exact home address.

### JSON output / export

```bash
# print JSON to stdout
python netscope.py --query "8.8.8.8" --json

# write JSON to file
python netscope.py --query "AS3356" --json --export as3356.json
```

### Active probing (use responsibly)

```bash
# enable ping/traceroute (only on networks you are authorized to probe)
python netscope.py --query "8.8.8.8" --active --active-count 4
```

### Prefix expansion (careful: may be slow)

```bash
# expand many prefixes (respect rate & API limits)
python netscope.py --query "AS3356" --expand-prefixes --max-prefixes 500 --rate 1.5
```

---

## Example workflow (quick)

```bash
# 1. create venv & install
python3 -m venv venv && source venv/bin/activate && pip install requests python-dotenv ipwhois netaddr

# 2. create .env with optional keys, then load it
set -o allexport; source .env; set +o allexport

# 3. run
python netscope.py --query "$(curl -s ifconfig.me)"
```

---

## Troubleshooting & notes

* **Missing package errors**: install via `pip install requests python-dotenv ipwhois netaddr`.
* **Slow runs**: large ASNs with many prefixes are slow to expand — use sampling or lower `--max-prefixes`.
* **Rate limits**: ip-api and other free endpoints have limits. Use `--rate` to space calls and rely on the cache (`~/.netscope_cache.json`).
* **Accuracy**: public geolocation is approximate; IP -> city translations reflect database entries, not precise device GPS.

---

## Safety & legal

* **Passive lookups only** by default — safe and respectful of remote infrastructure.
* **Active probing (`--active`)** uses system `ping` and `traceroute`. Only run these against hosts/networks you are allowed to probe.
* Use NetScope responsibly and within applicable laws and policies.

---

## Optional next steps (suggested improvements)

* Add multithreaded, rate-limited geolocation for faster expansion.
* Integrate a paid geolocation provider (MaxMind/IPinfo) for higher accuracy and quota.
* Produce an HTML map export of geolocated samples.
* Add unit tests and CI for reliability.

---

## License

Provided as-is for personal, academic and internal operational use. No warranty. Contributions & issues welcome.
