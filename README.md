<p align="center">
  <img src="vulnova/Logo/vulnova-logo-primary.svg" alt="VulNova" width="320">
</p>

# VulNova Observatory

**The threat-intelligence portal that extends the VulNova CETM platform — a CLI and web dashboard for CVE tracking, risk triage, exploit discovery, and cyber news.**

VulNova Observatory is the intelligence module of VulNova. You observe the
threat landscape through four instruments:

- **Atlas** — the complete CVE catalog (NVD)
- **Pulse** — the live cyber-news feed (14 sources)
- **Flare** — vendor/GHSA advisories, including those with no CVE assigned
- **Signal** — data-source connection health

Use the command line for fast lookups and automation, or the web dashboard to
browse the live CVE catalog and tagged news feed.

```
$ vulnova lookup CVE-2024-3094

 ╭─────────────────── CVE-2024-3094 ───────────────────╮
 │ Description: Malicious code in xz/liblzma...        │
 │                                                      │
 │   CVSS:          10.0 (CRITICAL)                    │
 │   EPSS:          93.2%                              │
 │   CISA KEV:      YES - Actively Exploited           │
 │   Triage Score:  97/100 (CRITICAL)                  │
 │                                                      │
 │ Recommendation: IMMEDIATE ACTION...                  │
 ╰──────────────────────────────────────────────────────╯
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Web Dashboard** | Browser UI with four instruments — Atlas, Pulse, Flare, and Signal (`vulnova web`) |
| **Atlas** | Newest-first CVE catalog from NVD with time-window, severity, KEV, keyword filters, sorting, expandable detail, and a force-refresh button |
| **Pulse** | Live cyber-news feed aggregating 14 security sources (RSS/Atom) |
| **Flare** | Vendor + open-source advisories (GHSA, OSV, Ubuntu, Red Hat, MSRC, Palo Alto, VMware), including those with **no CVE assigned** |
| **Signal** | Live connection-health board for every data source |
| **Entity Tagging** | News articles auto-tagged with CVEs, agencies (CISA…), products, countries, and threat keywords — click to filter |
| **CVE Lookup (CLI)** | Search by CVE ID, component name+version, or CPE string |
| **Risk Triage** | Deterministic 0-100 priority score: KEV + EPSS + CVSS + exploit maturity |
| **Exploit Intel** | Exploit-DB (local CSV), GitHub PoCs, Nuclei templates, Metasploit modules, and Vulhub environments |
| **CISA KEV** | Known Exploited Vulnerabilities catalog — #1 triage signal |
| **EPSS Score** | Exploit prediction probability (FIRST.org) |
| **Smart CPE Matching** | Rapidfuzz similarity scoring + vendor normalization |
| **SQLite Cache** | TTL-based caching — fast repeats, offline-friendly |
| **Output Modes** | Table · JSON · CSV · Silent (CLI) |

---

## Installation

### From source

```bash
git clone https://github.com/Cyber-VulNova/vulnova-observatory.git
cd vulnova-observatory
pip install -e .
```

This installs the `vulnova` command (and the short alias `vn`). If you'd rather
not install it, run everything through the module form instead:
`python -m vulnova.cli …`

### Requirements

- Python 3.10+
- No API keys required — every data source works key-free

---

## Quick Start

**Run in one command** (clone, then let the launcher create a venv, install, and start the dashboard):

```bash
git clone https://github.com/Cyber-VulNova/vulnova-observatory.git
cd vulnova-observatory

# Windows (PowerShell)
./run.ps1

# macOS / Linux
./run.sh
```

That's it — no API keys, no database setup. On first run it creates its own
local cache (`~/.vulnova/`) and pulls live data from the public sources. Pass
flags straight through, e.g. `./run.ps1 --port 8080 --refresh-hours 6`.

Prefer to do it manually?

```bash
pip install .

# Launch the web dashboard (opens your browser at http://127.0.0.1:5000)
vulnova web
# …or, without installing the package:
python -m vulnova.cli web

# Look up a CVE
vulnova lookup CVE-2024-3094

# Search by component + version
vulnova lookup "apache httpd 2.4.49"
```

---

## Web Dashboard

Start it with:

```bash
vulnova web                       # http://127.0.0.1:5000
vulnova web --port 8080           # custom port
vulnova web --host 0.0.0.0        # bind all interfaces

# If the package isn't installed, use the module form:
python -m vulnova.cli web --port 5000
```

The dashboard has four pages, switchable from the top navigation.

### Atlas — CVE Catalog

A live table of CVEs pulled from the NVD API v2, newest published first, each
row enriched with EPSS, CISA KEV status, and the VulNova triage score.

- **Filters:** time window (last 7 / 30 / 90 / 120 days, or all time), CVSS
  severity, "KEV only" toggle, and keyword search
- **Columns:** CVE ID, Triage score, CVSS, Severity, EPSS, KEV, Description,
  Published date, CWE, and a link to the NVD detail page
- **Sortable** by triage, CVSS, EPSS, or published date
- **Row expander** shows the full description, KEV action, recommendation,
  affected CPEs, and references
- Pagination with total match count; results cached in SQLite

### Pulse — Cyber News Feed

A live threat-intelligence feed aggregating RSS/Atom feeds from 14 security
sources, refreshed every 15 minutes and cached locally.

- **Filter** by source, by category (News · Research · Advisories), or search
  headlines
- **Entity tags** on every article — click any tag to filter the feed:
  - 🐛 **CVE** identifiers
  - 🏛️ **Agencies** (CISA, FBI, NSA, ENISA, Europol, …)
  - 📦 **Products / vendors** (Microsoft, Fortinet, Ivanti, VMware, …)
  - 🌐 **Countries** (including demonyms — "Chinese" → China)
  - 🏷️ **Threat keywords** (ransomware, zero-day, phishing, APT, …)

| Category | Sources |
|----------|---------|
| **News** | The Hacker News · BleepingComputer · The Register (Security) · SecurityWeek · Dark Reading · The Record · Krebs on Security |
| **Research** | SANS Internet Storm Center · Palo Alto Unit 42 · Cisco Talos Intelligence · Rapid7 Blog · Google Project Zero |
| **Advisories** | ZDI Published Advisories · ZDI Upcoming Advisories |

### Flare — Advisories

Security advisories aggregated from **multiple vendor sources** (no API key
needed), with first-class support for the ones VulNova's CVE-anchored views
miss — advisories that have **no CVE assigned**.

Sources (all free, no API key):
- **GitHub Advisory Database** (GHSA) — open-source ecosystems (npm, PyPI, Go, Rust, …), many with no CVE
- **Ubuntu Security Notices** (USN)
- **Red Hat Security Advisories** (RHSA)
- **Microsoft Security Response Center** (MSRC) — latest Patch Tuesday
- **Palo Alto Networks** advisories
- **VMware** — recent VMware vulnerabilities via NVD (Broadcom offers no clean no-key feed)
- **OSV.dev** — open-source ecosystem advisories (crates.io/RustSec, PyPI/PYSEC, Go); the primary **no-CVE** source, since these databases carry many advisories with no CVE assigned

> **Where the no-CVE advisories come from.** The vendor PSIRTs (Palo Alto,
> Microsoft, Red Hat, VMware) are CVE Numbering Authorities — they mint their
> own CVE IDs at disclosure, so their advisories almost always ship *with* a
> CVE. The no-CVE gap lives in the open-source ecosystems, which is why
> **GHSA** and **OSV.dev** (RustSec/PyPI/Go) are Flare's no-CVE sources.

Features:
- **"No CVE" filter** — the headline use case: surface advisories that never
  got (or don't yet have) a CVE
- Filter by **source**, **severity**, **ecosystem**, and **type**, plus keyword search
- Each card shows the advisory ID (GHSA/USN/RHSA), source, severity + CVSS,
  affected packages, CWEs, EPSS, and — when present — a CVE badge linking
  straight into Atlas

New vendor sources are pluggable: add a small client that returns the shared
`Advisory` shape and register it — the merge, filters, and UI come for free.

### Signal — Source Status

A live status board for every data feed VulNova depends on: whether it's
reachable right now, when it last refreshed, how many items are cached, and
what each source is used for. Grouped by category with a one-click re-check.

When auto-refresh is enabled, Signal also shows a banner with the interval, the
**last refresh** time, and the **next refresh** time.

---

## Automatic Refresh

By default data is fetched on demand and cached per-source (each with its own
TTL — NVD ~30 min, GHSA ~1 h, KEV/OSV ~6 h, news ~15 min). You can also have
VulNova proactively force-refresh every source on a fixed interval so the
dashboard always serves warm, current data.

**In-process scheduler** (works under any WSGI server):

```bash
vulnova web --refresh-hours 6            # refresh every 6 hours
# or set an environment variable (picked up by create_app):
#   VULNOVA_REFRESH_HOURS=6
```

**External scheduler** (recommended for multi-worker production) — run the
one-shot command from cron / Task Scheduler / a PaaS scheduled job:

```bash
vulnova refresh                          # force-refresh all caches once
```

The current state is exposed at `GET /api/refresh-status` (auto on/off,
interval, last refresh, next refresh) and surfaced in the Signal page banner.

---

## CLI Usage

### CVE Lookup

Search by CVE ID, component name+version, or CPE string:

```bash
# By CVE ID
vulnova lookup CVE-2023-44487

# By component name + version
vulnova lookup "openssl 3.0.7"

# By CPE string
vulnova lookup "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
```

### Output Formats

```bash
vulnova lookup CVE-2023-44487                 # rich terminal table (default)
vulnova -o json lookup CVE-2023-44487         # JSON (pipe to jq, scripts)
vulnova -o csv lookup "apache httpd 2.4.49"   # CSV
vulnova -o silent lookup CVE-2023-44487       # silent (exit code only)
```

---

## Risk Triage Scoring

VulNova produces a deterministic **0-100 priority score** for every CVE:

| Component | Weight | Signal |
|-----------|--------|--------|
| CISA KEV | 35 pts | Is it actively exploited in the wild? |
| EPSS | 25 pts | What's the probability of exploitation? |
| CVSS | 25 pts | How severe is the base vulnerability? |
| Exploit Maturity | 15 pts | Are public exploits/PoCs available? |

### Severity Labels

| Score | Label | Action |
|-------|-------|--------|
| 80-100 | CRITICAL | Immediate patching required |
| 60-79 | HIGH | Prioritize patching this week |
| 40-59 | MEDIUM | Plan for next maintenance window |
| 20-39 | LOW | Regular patching cycle |
| 0-19 | INFO | Monitor for changes |

---

## Data Sources

| Source | What it provides | Update frequency |
|--------|-----------------|------------------|
| [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVE details, CVSS, CPEs | Real-time |
| [EPSS](https://www.first.org/epss/) | Exploit probability scores | Daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | ~Weekly |
| [ExploitDB](https://www.exploit-db.com/) | Public exploits (local CSV) | Auto-downloaded, ~7 d refresh |
| [GitHub API](https://docs.github.com/en/rest) | PoC repositories | Real-time |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Detection templates (path-based) | ~12 h cache |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Exploit modules (offline metadata index) | ~7 d cache |
| [Vulhub](https://github.com/vulhub/vulhub) | Docker PoC environments | Real-time |
| [GitHub Advisory DB](https://github.com/advisories) | Ecosystem advisories for Flare (incl. no-CVE) | ~1 h cache |
| [Ubuntu USN](https://ubuntu.com/security/notices) | Ubuntu security notices for Flare | ~1 h cache |
| [Red Hat RHSA](https://access.redhat.com/security/security-updates/) | Red Hat security advisories for Flare | ~1 h cache |
| [Microsoft MSRC](https://msrc.microsoft.com/update-guide) | Microsoft advisories for Flare (CVRF) | ~1 h cache |
| [Palo Alto](https://security.paloaltonetworks.com/) | Palo Alto advisories for Flare (RSS) | ~1 h cache |
| VMware (via [NVD](https://nvd.nist.gov/)) | Recent VMware vulnerabilities for Flare | ~1 h cache |
| [OSV.dev](https://osv.dev) | Open-source advisories (RustSec/PyPI/Go) for Flare — the no-CVE source | ~6 h cache |
| 14 news feeds (RSS/Atom) | Cyber news for Pulse | Every 15 min |

---

## Configuration

Configuration and cached data live in `~/.vulnova/`:

```
~/.vulnova/
├── config.json        # General settings (e.g. cache TTL)
├── cache.db           # SQLite response cache (all sources, TTL-based)
└── exploitdb/
    └── files_exploits.csv  # Local ExploitDB mirror (downloaded on demand)
```

### config.json options

```json
{
  "cache_ttl": 86400
}
```

---

## Deployment

VulNova Observatory ships with a production `Dockerfile` and a `Procfile`. It
runs under gunicorn via the app factory `vulnova.web.app:create_app()`.

### Docker (any host)

```bash
docker build -t vulnova-observatory .
docker run -p 8000:8000 -v vulnova-data:/data -e VULNOVA_REFRESH_HOURS=6 vulnova-observatory
# open http://localhost:8000
```

### Render (Blueprint)

Push the repo, then in Render choose **New + → Blueprint** and select it — Render
reads `render.yaml`. Free instances sleep when idle, and the cache is ephemeral
unless you attach a disk at `/data`.

### Railway / Fly.io / Heroku-style

Use the `Dockerfile` directly, or the `Procfile`:

```
web: gunicorn "vulnova.web.app:create_app()" --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 120
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `PORT` | Port to bind (set automatically by most platforms). |
| `VULNOVA_REFRESH_HOURS` | Auto-refresh interval in hours (e.g. `6`). Unset/`0` disables. |
| `VULNOVA_BASIC_AUTH_USER` / `VULNOVA_BASIC_AUTH_PASS` | When **both** are set, the entire site requires HTTP Basic Auth. |
| `HOME` | Root of the app data dir (`$HOME/.vulnova`); the image sets it to `/data`. |

### Before exposing it publicly

- **Authentication:** there is no auth by default. Set the Basic Auth env vars
  above and/or front the app with a reverse proxy. Always serve over HTTPS.
- **Refresh endpoints:** `?refresh=1` triggers outbound fetches — keep it behind
  auth and/or rate-limit it on public instances (the manual refresh buttons are
  hidden by default).
- **Persistence:** mount a volume at `/data` to keep the SQLite cache warm
  across restarts; otherwise it refetches on cold start.

---

## Architecture

```
vulnova/
├── cli.py                 # Click CLI entry point (web, lookup)
├── commands/
│   └── lookup.py          # CVE lookup command
├── core/
│   ├── config.py          # Configuration & cache settings
│   ├── cache.py           # SQLite TTL cache
│   ├── triage.py          # Risk scoring engine
│   ├── cpe_match.py       # Smart CPE matching (rapidfuzz)
│   ├── cvss.py            # CVSS parsing / scoring helpers
│   ├── tagger.py          # News entity tagger (CVE/agency/product/country/keyword)
│   └── output.py          # Output formatting (Rich)
├── sources/
│   ├── nvd.py             # NVD API v2
│   ├── epss.py            # EPSS (FIRST.org)
│   ├── kev.py             # CISA KEV catalog
│   ├── exploitdb.py       # ExploitDB local CSV
│   ├── github_poc.py      # GitHub PoC repo search (ranked, filtered)
│   ├── nuclei.py          # Nuclei Templates (path-based resolution)
│   ├── metasploit.py      # Metasploit modules (offline metadata index)
│   ├── vulhub.py          # Vulhub Docker environments
│   ├── news.py            # Pulse news aggregator (14 RSS/Atom feeds)
│   ├── ghsa.py            # GitHub Advisory Database (Flare)
│   └── advisories.py      # Flare multi-source aggregator (GHSA + Ubuntu + Red Hat + MSRC + Palo Alto + VMware + OSV)
└── web/
    ├── app.py             # Flask app (Atlas / Pulse / Flare / Signal routes + APIs)
    ├── templates/         # index.html (Atlas), news.html (Pulse), flare.html, sources.html (Signal), cve.html
    └── static/            # style.css, app.js, news.js, flare.js, cve.js, sources.js
```

---

## Contributing

Contributions are welcome:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/Cyber-VulNova/vulnova-observatory.git
cd vulnova-observatory
pip install -e ".[dev]"
```

---

## Support

VulNova Observatory is free and maintained in my spare time. If it's useful to
you, you can help cover the upkeep (hosting, data-source monitoring, and new
features):

<a href="https://www.buymeacoffee.com/vulnova" target="_blank">
  <img src="https://img.shields.io/badge/Buy%20me%20a%20coffee-support%20maintenance-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee">
</a>

☕ **[buymeacoffee.com/vulnova](https://www.buymeacoffee.com/vulnova)**

You can also use the **Sponsor** button at the top of the repository. Every bit
is appreciated and goes toward keeping the project running.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

VulNova is a security research and vulnerability management tool. Use it
responsibly and only against systems you are authorized to assess. The authors
are not responsible for misuse.
