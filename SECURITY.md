# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for security problems.

- Preferred: use GitHub's private vulnerability reporting on this repository
  (the **Security** tab → **Report a vulnerability**).
- We aim to acknowledge reports within a few days and will keep you updated on
  remediation progress.

Please include a clear description, reproduction steps, and the potential
impact so we can triage quickly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Deploying VulNova Observatory Safely

VulNova Observatory is a threat-intelligence dashboard intended to be run by
its operator. Keep the following in mind before exposing it:

- **No built-in authentication.** The web UI and JSON APIs are unauthenticated.
  Do not expose a public instance without putting it behind your own
  authentication and a reverse proxy.
- **Refresh triggers outbound work.** Endpoints that force a refresh
  (`?refresh=1`) cause the server to re-fetch from upstream APIs and download
  data (e.g. OSV ecosystem dumps are tens of MB). On a public instance,
  rate-limit or disable these to avoid abuse and upstream rate-limit issues.
  The manual force-refresh buttons in the UI are hidden by default for this
  reason; freshness is handled by the optional 6-hour auto-refresh.
- **Outbound network only.** VulNova fetches from public data sources (NVD,
  EPSS, CISA KEV, GitHub Advisory DB, OSV.dev, vendor feeds, RSS). It does not
  require any API keys and does not transmit your data to third parties.
- **Run behind a production WSGI server** (gunicorn/waitress), not the Flask
  development server, and keep `debug=False`.
- **Treat all fetched content as untrusted data** — it originates from external
  sources.

## Data & Secrets

VulNova stores its cache and any optional configuration under `~/.vulnova/`
(outside the repository). No credentials are required to run it. Never commit
`.env` files, tokens, or other secrets — see `.gitignore`.
