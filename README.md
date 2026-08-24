<p align="center">
  <img src="vulnova/Logo/vulnova-logo-primary.svg" alt="VulNova" width="320">
</p>

# VulNova Observatory

**The threat-intelligence portal that extends the VulNova CETM platform — a CLI and web dashboard for CVE tracking, risk triage, exploit discovery, and cyber news.**

VulNova Observatory is the intelligence module of VulNova. You observe the
threat landscape through four instruments:

- **Atlas** — the complete CVE catalog (NVD)
- **Pulse** — the live cyber-news feed (14 sources)
- **Signal** — data-source connection health
- **Flare** — vendor/GHSA advisories *(planned)*

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
| **Web Dashboard** | Browser UI with the Atlas CVE catalog and the Pulse news feed (`vulnova web`) |
| **VulNova Atlas** | Newest-first CVE catalog from NVD with time-window, severity, KEV, keyword filters, sorting, and expandable detail |
| **VulNova Pulse** | Live cyber-news feed aggregating 14 security sources (RSS/Atom) |
| **Entity Tagging** | News articles auto-tagged with CVEs, agencies (CISA…), products, countries, and threat keywords — click to filter |
| **CVE Lookup (CLI)** | Search by CVE ID, component name+version, or CPE string |
| **Risk Triage** | Deterministic 0-100 priority score: KEV + EPSS + CVSS + exploit maturity |
| **Local-AI Briefing** | `--summarize` writes a plain-language triage briefing via a local LLM (offline) |
| **Reports** | `--report file.md` / `file.html` — HTML prints straight to PDF |
| **Doctor** | One command to check keys, connectivity, cache, and LLM readiness |
| **Asset Scanning** | Fingerprint a live URL → auto CVE scan per detected technology |
| **Batch Scanning** | Scan multiple URLs from a file with concurrency control |
| **Exploit-DB** | Local-indexed CSV, matched by CVE ID + fuzzy title |
| **GitHub PoCs** | GitHub API search (stars ranked, CVE-in-name first, aggregator lists filtered) |
| **Vulhub** | Docker-based PoC environments auto-discovered |
| **CISA KEV** | Known Exploited Vulnerabilities catalog — #1 triage signal |
| **Nuclei Templates** | Ready-to-fire templates from ProjectDiscovery |
| **Metasploit** | Module lookup with direct `use` command |
| **EPSS Score** | Exploit prediction probability (FIRST.org) |
| **Smart CPE Matching** | Rapidfuzz similarity scoring + vendor normalization |
| **SQLite Cache** | TTL-based caching — fast repeats, offline-friendly |
| **Output Modes** | Table · JSON · CSV · Silent (CLI) |
| **API Key Storage** | NVD + GitHub tokens stored in `~/.vulnova/` |

---

## Installation

### From source (recommended for development)

```bash
git clone https://github.com/vulnova/vulnova.git
cd vulnova
pip install -e .
```

### From PyPI (when published)

```bash
pip install vulnova
```

Both `vulnova` and the short alias `vn` are installed as console commands.

### Requirements

- Python 3.10+
- Optional: [Ollama](https://ollama.ai) for local AI briefings

---

## Quick Start

```bash
# Launch the web dashboard (opens your browser at http://127.0.0.1:5000)
vulnova web

# Configure API keys (optional but recommended for higher rate limits)
vulnova set-key nvd YOUR_NVD_API_KEY
vulnova set-key github YOUR_GITHUB_TOKEN

# Health check
vulnova doctor

# Look up a CVE
vulnova lookup CVE-2024-3094

# Search by component + version
vulnova lookup "apache httpd 2.4.49"

# Scan a live URL, or batch-scan from a file
vulnova scan https://example.com
vulnova batch urls.txt --concurrency 10
```

---

## Web Dashboard

Start it with:

```bash
vulnova web                       # http://127.0.0.1:5000
vulnova web --port 8080           # custom port
vulnova web --host 0.0.0.0        # bind all interfaces
```

The dashboard has three pages, switchable from the top navigation.

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

### Signal — Source Status

A live status board for every data feed VulNova depends on: whether it's
reachable right now, when it last refreshed, how many items are cached, and
what each source is used for. Grouped by category with a one-click re-check.

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

# With an AI briefing
vulnova lookup CVE-2024-3094 --summarize

# Generate a report
vulnova lookup CVE-2024-3094 --report report.html
```

### Asset Scanning

Fingerprint a live URL and automatically scan for CVEs per detected technology:

```bash
vulnova scan https://target.com
vulnova scan https://target.com --report scan_results.html
```

### Batch Scanning

Scan multiple URLs from a file (one URL per line) with concurrency control:

```bash
vulnova batch urls.txt
vulnova batch urls.txt --concurrency 20
vulnova batch urls.txt -c 10 --report batch_report.html
```

### Output Formats

```bash
vulnova lookup CVE-2023-44487                 # rich terminal table (default)
vulnova -o json lookup CVE-2023-44487         # JSON (pipe to jq, scripts)
vulnova -o csv lookup "apache httpd 2.4.49"   # CSV
vulnova -o silent lookup CVE-2023-44487       # silent (exit code only)
```

### Reports

```bash
vulnova lookup CVE-2024-3094 --report vuln_report.md    # Markdown
vulnova lookup CVE-2024-3094 --report vuln_report.html  # HTML (prints to PDF)
vulnova scan https://target.com --report scan.html
```

### Doctor

```bash
vulnova doctor
```

Checks API key configuration, connectivity to all data sources, SQLite cache
health, ExploitDB CSV availability, and local LLM (Ollama) readiness.

### API Key Management

```bash
vulnova set-key nvd YOUR_KEY       # https://nvd.nist.gov/developers/request-an-api-key
vulnova set-key github YOUR_TOKEN  # higher GitHub API rate limits
```

Keys are stored in `~/.vulnova/keys.json` with restricted permissions. You can
also use environment variables:

```bash
export VULNOVA_NVD_KEY=your_key
export VULNOVA_GITHUB_TOKEN=your_token
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

## Local AI Briefings

VulNova uses [Ollama](https://ollama.ai) for offline, private AI triage
briefings. All inference happens locally — no data leaves your machine.

```bash
curl -fsSL https://ollama.ai/install.sh | sh   # install Ollama
ollama pull mistral                            # pull a model
vulnova lookup CVE-2024-3094 --summarize       # generate a briefing
```

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
| 14 news feeds (RSS/Atom) | Cyber news for Pulse | Every 15 min |

---

## Configuration

Configuration is stored in `~/.vulnova/`:

```
~/.vulnova/
├── config.json        # General settings (cache TTL, LLM model, etc.)
├── keys.json          # API keys (NVD, GitHub) - chmod 600
├── cache.db           # SQLite response cache
└── exploitdb/
    └── files_exploits.csv  # Local ExploitDB mirror (downloaded on demand)
```

### config.json options

```json
{
  "cache_ttl": 86400,
  "llm_model": "mistral",
  "llm_endpoint": "http://localhost:11434"
}
```

---

## Architecture

```
vulnova/
├── cli.py                 # Click CLI entry point (lookup, scan, batch, doctor, web, set-key)
├── commands/
│   ├── lookup.py          # CVE lookup command
│   ├── scan.py            # Asset scanning command
│   ├── batch.py           # Batch scanning command
│   └── doctor.py          # Health check command
├── core/
│   ├── config.py          # Configuration & key management
│   ├── cache.py           # SQLite TTL cache
│   ├── triage.py          # Risk scoring engine
│   ├── cpe_match.py       # Smart CPE matching (rapidfuzz)
│   ├── scanner.py         # URL fingerprinting
│   ├── batch.py           # Async batch scanner
│   ├── tagger.py          # News entity tagger (CVE/agency/product/country/keyword)
│   ├── llm.py             # Local LLM client (Ollama)
│   ├── report.py          # Report generation (MD/HTML)
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
│   └── news.py            # Pulse news aggregator (14 RSS/Atom feeds)
└── web/
    ├── app.py             # Flask app (CVE table + Pulse routes/APIs)
    ├── templates/         # index.html (Atlas), news.html (Pulse), cve.html, sources.html (Signal)
    └── static/            # style.css, app.js, news.js, cve.js, sources.js
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
git clone https://github.com/vulnova/vulnova.git
cd vulnova
pip install -e ".[dev]"
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

VulNova is a security research and vulnerability management tool. Use it
responsibly and only against systems you are authorized to assess. The authors
are not responsible for misuse.
