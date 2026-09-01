# VulNova Observatory — Backlog

A running log of pending work, open decisions, and known gaps. This is an
internal reference (the old in-app Backlog page was removed on purpose). Edit
freely — check items off as they land.

_Last updated: 2026-08-31_

---

## Open decisions

- [x] **EPSS column on the Atlas table.** Resolved with **option (c)**: kept the
  column (still drives Sort-by-EPSS + the High-EPSS preset) but visually
  de-emphasized negligible values (< 1% dimmed, ≥ 10% highlighted). Note: "no
  value until 30 days old" was a misconception — EPSS is a daily-updated 30-day
  probability, valid from day one.

## Planned features (not built yet)

- [ ] New data-feed integrations — see "Candidate TIP feed integrations" below
  (CISA Advisories/ICS RSS, vendor PSIRTs, CERTs, CSAF, Vulnrichment/ADP, a new
  Intelligence/IOC area, etc.).

## Candidate TIP feed integrations (from `TIP/` registry, ~150 feeds)

Gap analysis vs. what's already wired in. Legend: **[easy]** = free + machine-readable
(RSS/JSON, no auth); **[key]** = needs an API key. Ordered by value/effort.

### Already integrated (reference)
- **Pulse/News:** The Hacker News, BleepingComputer, The Register, SecurityWeek,
  Dark Reading, The Record, Krebs, SANS ISC, Unit 42, Cisco Talos, Rapid7,
  Project Zero, ZDI (published + upcoming).
- **Flare/Advisories:** GitHub GHSA, Ubuntu USN, Red Hat, Palo Alto PSIRT,
  Microsoft MSRC, VMware/Broadcom, OSV (RustSec/PyPI/Go).
- **Core intel:** NVD, KEV, EPSS, ATT&CK, CAPEC, CVEfeed, Exploit-DB, GitHub PoC,
  Metasploit, Nuclei, Vulhub, Ransomware.live.

### Recommended first (biggest value, least effort)
- [~] **CISA Cybersecurity Advisories RSS** -> Flare — DEFERRED: the RSS endpoint
  returns HTTP 403 to automated fetches (Cloudflare bot-block), even with a
  browser UA. Follow-up: ingest via CISA **CSAF JSON** instead, or verify from
  the deploy IP.
- [~] **CISA ICS Advisories RSS** -> Flare — DEFERRED, same 403 as above.
- [x] **Top exploited-vendor PSIRTs** -> Flare: shipped **Cisco** + **Fortinet**
  (both live RSS). Ivanti/Citrix/F5/Apache/OpenSSH have no reliable public RSS →
  deferred (would need HTML scraping or CSAF).
- [x] **Threat-research blogs** -> Pulse: shipped **Microsoft Security Blog,
  ESET, SentinelLabs, Sophos X-Ops, watchTowr**. (Mandiant RSS empty, Google TAG
  404, Trend Micro SSL-fails → dropped.)
- [x] **Government CERT feeds** -> Flare: shipped **CERT-FR (ANSSI)**,
  **JPCERT/CC**, and **Debian DSA** via the new RSS advisory client.

### News / Pulse - missing
- [ ] Threat-research blogs [easy RSS]: Microsoft Security Blog / Threat Intelligence,
  Google TAG, Mandiant, CrowdStrike, ESET WeLiveSecurity, Kaspersky Securelist,
  Trend Micro, Sophos X-Ops, SentinelLabs, Bitdefender Labs, Huntress, Qualys TRU,
  Tenable Research, Eclypsium, watchTowr Labs.
- [ ] Research/disclosure [easy]: Packet Storm, Full Disclosure list, CERT/CC Vulnerability Notes.

### Advisories / Flare - missing
- [ ] Vendor PSIRTs [mostly easy RSS/JSON]: Cisco PSIRT, Fortinet PSIRT, Ivanti,
  Citrix, F5, Juniper PSIRT, Atlassian, GitLab, Oracle CPU, SAP, IBM, Adobe, Apple,
  Google Chrome / Android, Mozilla.
- [ ] OS / ecosystem [easy]: Debian, SUSE, Apache httpd, OpenSSH, Kubernetes CVE feed,
  FreeBSD, Alpine, Chainguard/Wolfi, Linux Kernel CVE, WordPress/Patchstack.
  (Several already partially flow through OSV.)
- [ ] Government CERTs [easy where RSS exists]: CERT-EU, CERT-FR / ANSSI, UK NCSC,
  JPCERT/CC, CCCS Canada, ACSC Australia, CERT-In, ENISA, CERT.PL, CERT.at, INCIBE.
- [ ] Standards / enrichment: CISA Vulnrichment/ADP (SSVC + enrichment), CSAF
  (normalized vendor advisories), MSRC CVRF API (machine-readable).

### Intelligence - would be a NEW area (no dedicated intel/IOC surface today)
- [ ] Exploit/PoC feeds [easy]: Exploit-DB RSS, Packet Storm, watchTowr.
- [ ] Ransomware tracking [easy]: Ransomwatch, CISA StopRansomware, Ransomware.live
  victim/group stream (currently used only for CVE->group links).
- [ ] IOC / CTI - free no-auth: abuse.ch URLhaus, Feodo Tracker, SSL Blacklist;
  Spamhaus DROP, Blocklist.de, FireHOL, CINSscore.
- [ ] IOC / CTI - [key]: abuse.ch ThreatFox & MalwareBazaar, AlienVault OTX,
  GreyNoise, Shodan, Censys, AbuseIPDB.
- [ ] Detection content [easy]: SigmaHQ, Emerging Threats rules, LOLBAS, GTFOBins
  (pair naturally with the ATT&CK page).

## Small tweaks (offered, low effort)

- [x] Atlas stat pill: now appends active filters + "· filtered" so the count isn't misleading.
- [x] Removed the dead `.backlog-*` CSS from `vulnova/web/static/style.css`.

## Known limitations (by design / data-driven — track, may not be "fixable")

- [ ] **CVE → ATT&CK coverage is sparse** for memory-safety and deserialization
  CWEs (e.g. CWE-125, CWE-416, CWE-502). MITRE's CWE→CAPEC→ATT&CK data simply
  has no technique mapping for these; the panel shows an honest empty-state.
- [ ] **Ransomware group → CVE** links only cover groups that populate
  Ransomware.live's structured `vulnerabilities` field (~10 of ~394 groups →
  ~51 CVEs). Coverage grows as Ransomware.live curates more.

## Ops / deployment to-dos (your side, not code)

- [ ] Set API keys in the hosting platform's environment:
  `NVD_API_KEY`, `CVEFEED_API_KEY`, `RANSOMWARE_LIVE_API_KEY`.
- [ ] Optional: upgrade to **CVEfeed Pro** — its exploit-intel / EPSS / CWE
  endpoints return 403 on the free tier.

---

## Recently shipped (for context)

_(Legend note: `[~]` above = attempted but deferred with a reason.)_

- [x] Pulse: +5 threat-research feeds (Microsoft, ESET, SentinelLabs, Sophos X-Ops, watchTowr) → 19 sources.
- [x] Flare: new RSS advisory client + Cisco, Fortinet, CERT-FR, JPCERT/CC, Debian (145 advisories) with source filter + Signal catalog entry.
- [x] Atlas: "· filtered" stat pill; EPSS low-value de-emphasis; removed dead backlog CSS.
- [x] README updated to reflect ATT&CK, EPSS, ransomware linkage, new feeds, and optional API keys.
- [x] Ransomware-group panel on the CVE page (Ransomware.live Pro API).
- [x] CVE → ATT&CK technique panel (CWE→CAPEC→ATT&CK); defaults to high-confidence
  (direct) mappings, related ones behind a toggle.
- [x] EPSS Prediction page (`/epss`): probability ranking, band stats, and an
  explainable VulNova exploitation-risk score.
- [x] ~5x faster CVE detail pages (parallelized the external lookups).
- [x] Atlas cleanup: removed the redundant "Avail" column, removed the small
  vector box (main search bar handles vectors), RCE is now confirmed-only, and
  the ATT&CK panel shows an explicit empty-state instead of vanishing.
