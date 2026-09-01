# VulNova Observatory — Backlog

A running log of pending work, open decisions, and known gaps. This is an
internal reference (the old in-app Backlog page was removed on purpose). Edit
freely — check items off as they land.

_Last updated: 2026-08-31_

---

## Open decisions (need a call before building)

- [ ] **EPSS column on the Atlas table.** Note: "no value until 30 days old" is
  a misconception — EPSS is a daily-updated probability of exploitation *in the
  next 30 days*, valid from day one (new CVEs just tend to start low). Decide:
  - (a) keep as-is (drives "Sort by EPSS" + the "High EPSS" preset), or
  - (b) remove it from the Atlas table but keep the EPSS page, CVE detail, and sort/preset, or
  - (c) keep but visually de-emphasize low values.

## Planned features (not built yet)

- [ ] **CISA Vulnrichment / ADP** enrichment (CVSS, CWE, KEV context added by CISA ADP).
- [ ] **CISA advisories + ICS advisories** (RSS) as a feed/source.
- [ ] **CSAF vendor advisories** integration (structured vendor security advisories).

## Small tweaks (offered, low effort)

- [ ] Atlas stat pill: show "X of Y · filtered" when a search/filter is active, so the count isn't misleading.
- [ ] Remove dead `.backlog-*` CSS left in `vulnova/web/static/style.css` from the removed Backlog page.

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

- [x] Ransomware-group panel on the CVE page (Ransomware.live Pro API).
- [x] CVE → ATT&CK technique panel (CWE→CAPEC→ATT&CK); defaults to high-confidence
  (direct) mappings, related ones behind a toggle.
- [x] EPSS Prediction page (`/epss`): probability ranking, band stats, and an
  explainable VulNova exploitation-risk score.
- [x] ~5x faster CVE detail pages (parallelized the external lookups).
- [x] Atlas cleanup: removed the redundant "Avail" column, removed the small
  vector box (main search bar handles vectors), RCE is now confirmed-only, and
  the ATT&CK panel shows an explicit empty-state instead of vanishing.
