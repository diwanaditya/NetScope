# NetScope

[![GitHub Repo](https://img.shields.io/badge/github-diwanaditya/NetScope-blue)](https://github.com/diwanaditya/NetScope)  
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)  

> **NetScope** is a terminal-based tool to inspect ASNs, IP addresses, and ISPs.  
> It provides comprehensive network intelligence in a single CLI report using multiple reliable data sources.

Repository: [https://github.com/diwanaditya/NetScope](https://github.com/diwanaditya/NetScope)

---

## Table of Contents

1. [Introduction](#introduction)  
2. [Key Features](#key-features)  
3. [Why NetScope Exists](#why-netscope-exists)  
4. [How NetScope Works](#how-netscope-works)  
5. [System Requirements](#system-requirements)  
6. [Installation & Setup](#installation--setup)  
7. [Environment Variables](#environment-variables)  
8. [Usage](#usage)  
9. [Output Details](#output-details)  
10. [Contributing](#contributing)  
11. [License](#license)  

---

## Introduction

**NetScope** is a Python utility designed for network analysts, security researchers, and IT professionals.  
It aggregates information from public network databases and APIs to provide a comprehensive view of any ASN, IP address, or ISP.  

---

## Key Features

- ASN / Organization Lookup  
- Announced IPv4/IPv6 Prefixes  
- Geolocation sampling (country, city, latitude, longitude, ISP)  
- Peering Information (upstreams, peers, customers)  
- Technical / Abuse Contacts  
- Optional Active Analysis (ping/traceroute)  
- Pretty-printed terminal output or JSON for automation  
- Local caching for faster repeated queries  

---

## Why NetScope Exists

- Simplify network intelligence collection from multiple sources  
- Single terminal-friendly tool without multiple web queries  
- Combine passive and optional active analysis  
- Portable, audit-friendly, single-file architecture  

---

## How NetScope Works

1. Accepts a **query**: ASN (`AS123`), IP (`1.2.3.4`), or ISP/organization name (`Level3`).  
2. Fetches data from multiple sources (BGPView, RIPEstat, PeeringDB, RDAP, IP geolocation).  
3. Optionally performs active probing (ping/traceroute).  
4. Aggregates results into structured terminal report or JSON output.  

---

## System Requirements

- Python 3.9+  
- Internet connection  
- Optional dependencies: `ipwhois`, `netaddr`, `python-dotenv`  
- Works on Linux, macOS, and Windows (PowerShell)  

---

## Installation & Setup

1. **Clone the repository**
```
git clone https://github.com/diwanaditya/NetScope
cd NetScope
```
Create and activate a Python virtual environment

# Linux / macOS
```
python3 -m venv venv
source venv/bin/activate
```
# Windows (PowerShell)
```
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install required packages

``` 
pip install requests ipwhois netaddr python-dotenv 
```


Verify installation

``` 
python netscope.py --query "8.8.8.8"
```


Optional: Check your public IP and query it:

```
curl ifconfig.me
python netscope.py --query "YOUR_PUBLIC_IP"
```
Environment Variables

Some features may require API keys or optional settings. Create a .env file in the repository root:

# .env template
```
BGPVIEW_API_KEY=
PEERINGDB_API_KEY=
IPWHOIS_ENABLED=true
```

Load environment variables:

# Linux / macOS
```
set -o allexport; source .env; set +o allexport
```

Without .env, NetScope still works but enriched features may be limited.

Usage

Query by ASN
```
python netscope.py --query "AS3356"
```

Query by IP
```
python netscope.py --query "8.8.8.8"
```

Query by ISP / Organization
```
python netscope.py --query "Level3"
```

JSON Output
```
python netscope.py --query "8.8.8.8" --json
```

Enable Active Analysis
```
python netscope.py --query "8.8.8.8" --active --active-count 5
```

Expand Many Prefixes
```
python netscope.py --query "AS3356" --expand-prefixes --max-prefixes 100
```
Output Details

ASN / Organization info

Announced Prefixes

Geo Samples

Peering Counts

Technical / Abuse Contacts

Active Analysis (ping/traceroute)

Warnings / Notes

Contributing

Fork the repository

Create a new branch (git checkout -b feature-name)

Make your changes and test

Submit a Pull Request with description

# License

MIT License — see LICENSE
