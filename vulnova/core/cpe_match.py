"""Smart CPE Matching with rapidfuzz.

Uses fuzzy string matching and vendor normalization to find the best
CPE match for a given component name and version.
"""

import re
from dataclasses import dataclass

from rapidfuzz import fuzz, process


# Common vendor name normalizations
VENDOR_ALIASES = {
    "apache": ["apache", "apache software foundation", "asf"],
    "microsoft": ["microsoft", "ms", "msft"],
    "google": ["google", "google inc", "google llc", "alphabet"],
    "oracle": ["oracle", "oracle corporation", "sun", "sun microsystems"],
    "redhat": ["redhat", "red hat", "red_hat"],
    "debian": ["debian", "debian project"],
    "ubuntu": ["ubuntu", "canonical"],
    "linux": ["linux", "linux kernel", "kernel.org"],
    "openssh": ["openssh", "openbsd"],
    "openssl": ["openssl", "openssl project"],
    "nginx": ["nginx", "f5"],
    "nodejs": ["nodejs", "node.js", "node"],
    "python": ["python", "python software foundation", "cpython"],
    "php": ["php", "php group", "php.net"],
    "wordpress": ["wordpress", "automattic"],
    "jquery": ["jquery", "jquery foundation", "js foundation"],
    "jenkins": ["jenkins", "jenkins project", "cloudbees"],
    "docker": ["docker", "docker inc", "moby"],
    "kubernetes": ["kubernetes", "k8s"],
    "elastic": ["elastic", "elasticsearch", "elastic nv"],
    "vmware": ["vmware", "broadcom"],
    "cisco": ["cisco", "cisco systems"],
    "ibm": ["ibm", "international business machines"],
    "samsung": ["samsung", "samsung electronics"],
    "apple": ["apple", "apple inc"],
    "adobe": ["adobe", "adobe systems"],
    "atlassian": ["atlassian", "atlassian pty"],
    "gitlab": ["gitlab", "gitlab inc"],
    "github": ["github", "github inc"],
}

# Reverse lookup: alias -> canonical vendor
_ALIAS_TO_VENDOR: dict[str, str] = {}
for vendor, aliases in VENDOR_ALIASES.items():
    for alias in aliases:
        _ALIAS_TO_VENDOR[alias.lower()] = vendor


@dataclass
class CPEMatch:
    """Result of a CPE matching operation."""
    cpe_string: str
    vendor: str
    product: str
    version: str
    score: float  # 0-100 similarity score
    match_type: str  # "exact", "fuzzy", "vendor_alias"


def normalize_vendor(vendor: str) -> str:
    """Normalize a vendor name to its canonical form.

    Args:
        vendor: Raw vendor name string.

    Returns:
        Canonical vendor name.
    """
    cleaned = vendor.lower().strip()
    cleaned = re.sub(r"[^a-z0-9\s]", "", cleaned)
    return _ALIAS_TO_VENDOR.get(cleaned, cleaned)


def parse_cpe(cpe_string: str) -> dict:
    """Parse a CPE 2.3 string into components.

    Example: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    parts = cpe_string.split(":")
    if len(parts) < 6:
        return {}
    return {
        "part": parts[2] if len(parts) > 2 else "",
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "",
        "update": parts[6] if len(parts) > 6 else "",
        "edition": parts[7] if len(parts) > 7 else "",
        "language": parts[8] if len(parts) > 8 else "",
    }


def build_cpe(vendor: str, product: str, version: str = "*", part: str = "a") -> str:
    """Build a CPE 2.3 string from components.

    Args:
        vendor: Vendor name (will be normalized).
        product: Product name.
        version: Version string (default: * for any).
        part: CPE part type (a=application, o=os, h=hardware).

    Returns:
        CPE 2.3 format string.
    """
    v = normalize_vendor(vendor).replace(" ", "_")
    p = product.lower().replace(" ", "_").replace("-", "_")
    return f"cpe:2.3:{part}:{v}:{p}:{version}:*:*:*:*:*:*:*"


def fuzzy_match_product(
    query: str,
    candidates: list[str],
    threshold: float = 60.0,
    limit: int = 5,
) -> list[tuple[str, float]]:
    """Find the best fuzzy matches for a product name.

    Args:
        query: The product name to match.
        candidates: List of known product names to match against.
        threshold: Minimum similarity score (0-100).
        limit: Maximum number of results.

    Returns:
        List of (candidate, score) tuples sorted by score descending.
    """
    if not candidates:
        return []

    results = process.extract(
        query.lower(),
        [c.lower() for c in candidates],
        scorer=fuzz.WRatio,
        limit=limit,
        score_cutoff=threshold,
    )
    # results are (match, score, index) tuples
    return [(candidates[r[2]], r[1]) for r in results]


def match_component_to_cpe(
    component: str,
    version: str,
    known_cpes: list[str],
    threshold: float = 65.0,
) -> list[CPEMatch]:
    """Match a component name + version to known CPE strings.

    Uses a combination of:
    - Exact matching on vendor/product
    - Vendor alias normalization
    - Fuzzy string matching with rapidfuzz

    Args:
        component: Component/product name (e.g., "Apache HTTP Server").
        version: Version string (e.g., "2.4.49").
        known_cpes: List of CPE strings to match against.
        threshold: Minimum fuzzy match score.

    Returns:
        List of CPEMatch results sorted by score descending.
    """
    component_lower = component.lower().strip()
    component_normalized = normalize_vendor(component_lower)
    matches: list[CPEMatch] = []

    for cpe in known_cpes:
        parsed = parse_cpe(cpe)
        if not parsed:
            continue

        cpe_vendor = parsed["vendor"].replace("_", " ")
        cpe_product = parsed["product"].replace("_", " ")
        cpe_version = parsed["version"]

        # Version check - if specified, must be compatible
        version_ok = (
            cpe_version == "*"
            or cpe_version == version
            or version == "*"
        )

        # Exact product match
        if component_lower == cpe_product or component_normalized == cpe_product:
            score = 100.0 if version_ok else 80.0
            matches.append(CPEMatch(
                cpe_string=cpe,
                vendor=parsed["vendor"],
                product=parsed["product"],
                version=cpe_version,
                score=score,
                match_type="exact",
            ))
            continue

        # Vendor alias match
        norm_cpe_vendor = normalize_vendor(cpe_vendor)
        if component_normalized == norm_cpe_vendor:
            score = 85.0 if version_ok else 70.0
            matches.append(CPEMatch(
                cpe_string=cpe,
                vendor=parsed["vendor"],
                product=parsed["product"],
                version=cpe_version,
                score=score,
                match_type="vendor_alias",
            ))
            continue

        # Fuzzy match on combined vendor+product
        combined = f"{cpe_vendor} {cpe_product}"
        similarity = fuzz.WRatio(component_lower, combined)

        if similarity >= threshold:
            # Boost score if version matches
            final_score = similarity if version_ok else similarity * 0.8
            matches.append(CPEMatch(
                cpe_string=cpe,
                vendor=parsed["vendor"],
                product=parsed["product"],
                version=cpe_version,
                score=final_score,
                match_type="fuzzy",
            ))

    # Sort by score descending
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches


def parse_component_query(query: str) -> tuple[str, str]:
    """Parse a component query string into (name, version).

    Examples:
        "apache httpd 2.4.49" -> ("apache httpd", "2.4.49")
        "jquery 3.6.0" -> ("jquery", "3.6.0")
        "openssl" -> ("openssl", "*")

    Args:
        query: Free-text component query.

    Returns:
        Tuple of (component_name, version).
    """
    # Try to find a version-like pattern at the end
    version_pattern = re.compile(
        r"\s+v?(\d+(?:\.\d+)+(?:[-._]\w+)?)\s*$", re.IGNORECASE
    )
    match = version_pattern.search(query)
    if match:
        version = match.group(1)
        name = query[:match.start()].strip()
        return (name, version)

    return (query.strip(), "*")
