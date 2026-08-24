"""Entity tagger for the VulNova Pulse news feed.

Scans article titles + summaries and extracts structured tags without any
heavy NLP dependency. Tag types:

    cve      - CVE identifiers (regex)
    agency   - government / national cyber bodies (CISA, FBI, ENISA, ...)
    product  - major vendors and products (Microsoft, Fortinet, Ivanti, ...)
    country  - countries, including demonyms/aliases (Chinese -> China)
    keyword  - threat / topic keywords (ransomware, zero-day, phishing, ...)

Matching strategy:
- Full multi-character terms are matched case-insensitively with word
  boundaries.
- Short uppercase acronyms (US, UK, EU, FBI) are matched case-sensitively
  to avoid false positives on common lowercase words.
- Aliases map many surface forms to one canonical label, then results are
  de-duplicated per (type, label).
"""

import re
from dataclasses import dataclass


# ─── CVE ──────────────────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ─── Dictionaries ───────────────────────────────────────────────────────────
# Each entry maps a canonical label -> list of surface aliases.
# Aliases that are short ALL-CAPS acronyms are matched case-sensitively.

AGENCIES: dict[str, list[str]] = {
    "CISA": ["CISA", "Cybersecurity and Infrastructure Security Agency"],
    "FBI": ["FBI"],
    "NSA": ["NSA"],
    "DHS": ["DHS"],
    "DOJ": ["DOJ", "Department of Justice"],
    "FTC": ["FTC"],
    "SEC": ["SEC"],
    "CIA": ["CIA"],
    "NCSC": ["NCSC", "National Cyber Security Centre"],
    "ENISA": ["ENISA"],
    "Europol": ["Europol"],
    "Interpol": ["Interpol"],
    "GCHQ": ["GCHQ"],
    "ACSC": ["ACSC", "Australian Cyber Security Centre"],
    "US-CERT": ["US-CERT", "CERT/CC", "CERT-EU"],
    "NIST": ["NIST"],
    "FSB": ["FSB"],
    "MI5": ["MI5"],
    "MI6": ["MI6"],
    "NCA": ["National Crime Agency"],
    "White House": ["White House"],
    "Pentagon": ["Pentagon"],
}

PRODUCTS: dict[str, list[str]] = {
    "Microsoft": ["Microsoft"],
    "Windows": ["Windows"],
    "Microsoft Exchange": ["Exchange Server", "Microsoft Exchange"],
    "Microsoft Office": ["Microsoft Office", "MS Office"],
    "SharePoint": ["SharePoint"],
    "Outlook": ["Outlook"],
    "Azure": ["Azure"],
    "Active Directory": ["Active Directory"],
    "Apple": ["Apple"],
    "iOS": ["iOS", "iPadOS"],
    "macOS": ["macOS", "Mac OS"],
    "Safari": ["Safari"],
    "Google": ["Google"],
    "Chrome": ["Chrome", "Chromium"],
    "Android": ["Android"],
    "Cisco": ["Cisco"],
    "Cisco IOS XE": ["IOS XE"],
    "Fortinet": ["Fortinet", "FortiOS", "FortiGate", "FortiManager", "FortiClient"],
    "Ivanti": ["Ivanti", "Pulse Secure", "Connect Secure"],
    "VMware": ["VMware", "ESXi", "vCenter", "vSphere"],
    "Citrix": ["Citrix", "NetScaler"],
    "Palo Alto Networks": ["Palo Alto", "PAN-OS", "GlobalProtect"],
    "SonicWall": ["SonicWall"],
    "Juniper": ["Juniper"],
    "F5": ["BIG-IP", "F5 Networks"],
    "Apache": ["Apache"],
    "Apache Struts": ["Struts"],
    "Log4j": ["Log4j", "Log4Shell"],
    "Atlassian": ["Atlassian", "Confluence", "Jira", "Bitbucket"],
    "GitLab": ["GitLab"],
    "GitHub": ["GitHub"],
    "Oracle": ["Oracle", "WebLogic"],
    "Java": ["Java"],
    "Adobe": ["Adobe", "Acrobat", "ColdFusion"],
    "Linux": ["Linux"],
    "OpenSSH": ["OpenSSH"],
    "OpenSSL": ["OpenSSL"],
    "WordPress": ["WordPress"],
    "MOVEit": ["MOVEit"],
    "Zimbra": ["Zimbra"],
    "SolarWinds": ["SolarWinds"],
    "Progress Software": ["Progress Software"],
    "Zoom": ["Zoom"],
    "Docker": ["Docker"],
    "Kubernetes": ["Kubernetes", "K8s"],
    "Jenkins": ["Jenkins"],
    "Samsung": ["Samsung"],
    "Qualcomm": ["Qualcomm"],
    "Intel": ["Intel"],
    "AMD": ["AMD"],
    "NVIDIA": ["NVIDIA"],
    "Zyxel": ["Zyxel"],
    "QNAP": ["QNAP"],
    "D-Link": ["D-Link"],
    "Netgear": ["Netgear"],
    "TP-Link": ["TP-Link"],
    "Veeam": ["Veeam"],
    "Barracuda": ["Barracuda"],
    "Sophos": ["Sophos"],
    "CrowdStrike": ["CrowdStrike"],
    "Okta": ["Okta"],
    "Firefox": ["Firefox", "Mozilla"],
    "PHP": ["PHP"],
    "MongoDB": ["MongoDB"],
    "Elastic": ["Elasticsearch", "Elastic"],
    "Salesforce": ["Salesforce"],
    "SAP": ["SAP"],
    "WhatsApp": ["WhatsApp"],
    "TikTok": ["TikTok"],
}

COUNTRIES: dict[str, list[str]] = {
    "United States": ["United States", "U.S.", "USA", "US", "American", "Americans"],
    "China": ["China", "Chinese", "Beijing"],
    "Russia": ["Russia", "Russian", "Russians", "Kremlin", "Moscow"],
    "North Korea": ["North Korea", "North Korean", "DPRK", "Pyongyang"],
    "Iran": ["Iran", "Iranian", "Iranians", "Tehran"],
    "Ukraine": ["Ukraine", "Ukrainian", "Ukrainians", "Kyiv"],
    "United Kingdom": ["United Kingdom", "UK", "U.K.", "Britain", "British", "England"],
    "India": ["India", "Indian", "Indians"],
    "Israel": ["Israel", "Israeli", "Israelis"],
    "Germany": ["Germany", "German", "Germans"],
    "France": ["France", "French"],
    "Japan": ["Japan", "Japanese"],
    "South Korea": ["South Korea", "South Korean", "Seoul"],
    "Australia": ["Australia", "Australian", "Australians"],
    "Canada": ["Canada", "Canadian", "Canadians"],
    "Brazil": ["Brazil", "Brazilian", "Brazilians"],
    "Pakistan": ["Pakistan", "Pakistani"],
    "Vietnam": ["Vietnam", "Vietnamese"],
    "Turkey": ["Turkey", "Turkish"],
    "Italy": ["Italy", "Italian", "Italians"],
    "Spain": ["Spain", "Spanish"],
    "Netherlands": ["Netherlands", "Dutch"],
    "Taiwan": ["Taiwan", "Taiwanese", "Taipei"],
    "Saudi Arabia": ["Saudi Arabia", "Saudi"],
    "Singapore": ["Singapore"],
    "Poland": ["Poland", "Polish"],
    "Belarus": ["Belarus", "Belarusian"],
}

KEYWORDS: dict[str, list[str]] = {
    "Ransomware": ["ransomware", "ransom"],
    "Zero-Day": ["zero-day", "zero day", "0-day", "0day"],
    "Phishing": ["phishing", "spear-phishing", "spearphishing", "smishing"],
    "Malware": ["malware"],
    "Data Breach": ["data breach", "breach", "data leak"],
    "APT": ["APT", "advanced persistent threat", "nation-state", "state-sponsored"],
    "Botnet": ["botnet"],
    "DDoS": ["DDoS", "denial of service"],
    "Supply Chain": ["supply chain", "supply-chain"],
    "Backdoor": ["backdoor"],
    "Spyware": ["spyware", "stalkerware"],
    "Trojan": ["trojan"],
    "RCE": ["remote code execution", "RCE"],
    "Privilege Escalation": ["privilege escalation", "privilege-escalation"],
    "Credential Theft": ["credential theft", "credential-stealing", "infostealer", "stealer"],
    "Exploit": ["exploit", "actively exploited", "in the wild"],
    "Espionage": ["espionage", "cyberespionage", "cyber-espionage"],
    "Extortion": ["extortion"],
    "Vulnerability": ["vulnerability", "vulnerabilities", "flaw", "flaws"],
    "Patch": ["patch tuesday", "security update", "patched"],
    "Data Wiper": ["wiper"],
    "Cryptomining": ["cryptomining", "cryptojacking", "cryptominer"],
    "Deepfake": ["deepfake", "deepfakes"],
    "Insider Threat": ["insider threat"],
}


@dataclass
class TagRule:
    type: str
    label: str
    regex: re.Pattern


def _is_acronym(alias: str) -> bool:
    """True if alias is a short all-caps acronym that needs case-sensitive match."""
    stripped = alias.replace("-", "").replace(".", "").replace("/", "")
    return alias.isupper() and len(stripped) <= 6 and stripped.isalpha()


def _compile_rules() -> list[TagRule]:
    """Compile all dictionary entries into ordered TagRules."""
    rules: list[TagRule] = []
    for tag_type, table in (
        ("agency", AGENCIES),
        ("product", PRODUCTS),
        ("country", COUNTRIES),
        ("keyword", KEYWORDS),
    ):
        for label, aliases in table.items():
            for alias in aliases:
                escaped = re.escape(alias)
                if _is_acronym(alias):
                    # Case-sensitive, word-boundary
                    pattern = re.compile(rf"\b{escaped}\b")
                else:
                    pattern = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
                rules.append(TagRule(tag_type, label, pattern))
    return rules


_RULES = _compile_rules()

# Priority ordering for display (most useful first)
_TYPE_ORDER = {"cve": 0, "agency": 1, "product": 2, "country": 3, "keyword": 4}


def extract_tags(*texts: str, max_tags: int = 12) -> list[dict]:
    """Extract structured tags from one or more text fragments.

    Args:
        *texts: Title, summary, etc. They are concatenated for scanning.
        max_tags: Maximum number of tags to return.

    Returns:
        List of {"type": ..., "label": ...} dicts, de-duplicated and ordered
        by type priority (cve, agency, product, country, keyword).
    """
    blob = " ".join(t for t in texts if t)
    if not blob:
        return []

    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # CVEs first
    for m in _CVE_RE.findall(blob):
        key = ("cve", m.upper())
        if key not in seen:
            seen.add(key)
            found.append(key)

    # Dictionary rules
    for rule in _RULES:
        key = (rule.type, rule.label)
        if key in seen:
            continue
        if rule.regex.search(blob):
            seen.add(key)
            found.append(key)

    # Order by type priority, keep CVEs/agencies/products ahead of keywords
    found.sort(key=lambda k: _TYPE_ORDER.get(k[0], 99))

    return [{"type": t, "label": l} for t, l in found[:max_tags]]


# ─── Product extraction from free-text descriptions ──────────────────────────
# Fallback for CVEs with no CNA "affected" data and no CPEs (rare). Targets the
# consistent phrasings used by common CNAs (VulDB, VulnCheck, GitLab, CPAN…).

_PRODUCT_PATTERNS = [
    # VulDB / Red Hat: "... has been found in <PRODUCT> <up to|version|N|.>"
    re.compile(
        r"(?:has\s+been\s+found|was\s+found|were\s+found|has\s+been\s+identified"
        r"|was\s+identified|has\s+been\s+detected|was\s+discovered)\s+in\s+"
        r"(?P<p>.+?)(?=\s+up\s+to|\s+before|\s+through|\s+version|\s+v?\d|[.,;:])",
        re.I),
    # "in <PRODUCT> allows/could/permits/enables/leads"
    re.compile(
        r"\bin\s+(?P<p>[A-Za-z0-9][\w.:\-/+ ]+?)\s+"
        r"(?:allows?|could|enables?|permits?|leads?|makes?|results?)\b", re.I),
    # Leading token: "<PRODUCT> before/through/versions/version/<=/N"
    re.compile(
        r"^(?P<p>[A-Za-z0-9][\w.:\-/+]*)\s+"
        r"(?:before|through|versions?|version|prior|<=|>=|<|>|\d)", re.I),
    # WordPress plugin/theme
    re.compile(
        r"\b(?:The\s+)?(?P<p>[A-Za-z0-9][\w.\-]*(?:\s+[\w.\-]+){0,6}?)\s+"
        r"(?:plugin|theme)\s+for\s+WordPress", re.I),
]

_LEADING_ARTICLE = re.compile(r"^(the|a|an)\s+", re.I)


def extract_product_text(description: str) -> str:
    """Best-effort product name pulled from a CVE description.

    Returns an empty string when no confident match is found.
    """
    if not description:
        return ""
    text = description.strip()
    for pat in _PRODUCT_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        p = _LEADING_ARTICLE.sub("", m.group("p").strip()).strip(" .,;:-")
        words = p.split()
        if len(words) > 8:
            p = " ".join(words[:8])
        if 1 < len(p) <= 80:
            return p
    return ""
