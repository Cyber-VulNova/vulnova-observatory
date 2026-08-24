"""CVSS vector parser.

Turns a CVSS vector string (v2.0, v3.0/3.1, or v4.0) into a list of
human-readable metric components for display.
"""

# Metric-name and value labels keyed by CVSS metric abbreviation.
# Covers the Base metrics for v2, v3.x, and v4.0.
_METRIC_LABELS = {
    # Shared / v3.x + v4.0 base
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "AT": ("Attack Requirements", {"N": "None", "P": "Present"}),  # v4.0
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required", "P": "Passive", "A": "Active"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),  # v3.x
    "C": ("Confidentiality", {"H": "High", "L": "Low", "N": "None", "P": "Partial", "C": "Complete"}),
    "I": ("Integrity", {"H": "High", "L": "Low", "N": "None", "P": "Partial", "C": "Complete"}),
    "A": ("Availability", {"H": "High", "L": "Low", "N": "None", "P": "Partial", "C": "Complete"}),
    # v4.0 vulnerable/subsequent-system impacts
    "VC": ("Confidentiality (Vulnerable)", {"H": "High", "L": "Low", "N": "None"}),
    "VI": ("Integrity (Vulnerable)", {"H": "High", "L": "Low", "N": "None"}),
    "VA": ("Availability (Vulnerable)", {"H": "High", "L": "Low", "N": "None"}),
    "SC": ("Confidentiality (Subsequent)", {"H": "High", "L": "Low", "N": "None"}),
    "SI": ("Integrity (Subsequent)", {"H": "High", "L": "Low", "N": "None"}),
    "SA": ("Availability (Subsequent)", {"H": "High", "L": "Low", "N": "None"}),
    # v2.0 only
    "Au": ("Authentication", {"M": "Multiple", "S": "Single", "N": "None"}),
}

# The base metrics we want to display, in order, so the breakdown reads well.
_DISPLAY_ORDER = [
    "AV", "AC", "AT", "PR", "UI", "Au", "S",
    "C", "I", "A",
    "VC", "VI", "VA", "SC", "SI", "SA",
]


def parse_vector(vector: str) -> list[dict]:
    """Parse a CVSS vector string into readable components.

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        List of {"metric": <full name>, "value": <readable value>, "abbr": <code>}
        in a sensible display order. Unknown metrics are skipped.
    """
    if not vector:
        return []

    # Drop a leading "CVSS:x.y" prefix if present
    parts = [p for p in vector.split("/") if ":" in p]
    found: dict[str, str] = {}
    for p in parts:
        key, _, val = p.partition(":")
        if key.upper() in ("CVSS",):
            continue
        found[key] = val

    components = []
    for abbr in _DISPLAY_ORDER:
        if abbr not in found:
            continue
        label_info = _METRIC_LABELS.get(abbr)
        if not label_info:
            continue
        name, value_map = label_info
        raw = found[abbr]
        components.append({
            "abbr": abbr,
            "metric": name,
            "value": value_map.get(raw, raw),
        })
    return components


def cvss_version_from_vector(vector: str) -> str:
    """Extract the CVSS version label from a vector string, if present."""
    if vector.startswith("CVSS:"):
        return vector.split("/", 1)[0].replace("CVSS:", "")
    # v2 vectors have no prefix
    return "2.0"
