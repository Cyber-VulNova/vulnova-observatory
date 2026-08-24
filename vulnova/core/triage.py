"""Risk Triage Scoring Engine.

Produces a deterministic 0-100 priority score combining:
- CISA KEV status (highest signal)
- EPSS score (exploit probability)
- CVSS base score
- Exploit maturity (public exploits, PoCs available)

Weights:
- KEV: 35 points (binary - in KEV or not)
- EPSS: 25 points (scaled by probability)
- CVSS: 25 points (scaled from 0-10 to 0-25)
- Exploit Maturity: 15 points (based on available exploits)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ExploitMaturity(Enum):
    """Exploit maturity levels."""
    NOT_DEFINED = "not_defined"
    UNPROVEN = "unproven"  # No known exploits
    POC = "poc"  # Proof of concept exists
    FUNCTIONAL = "functional"  # Functional exploit exists
    WEAPONIZED = "weaponized"  # Used in active attacks (KEV)


@dataclass
class TriageBreakdown:
    """Detailed breakdown of the triage score."""
    kev_score: float = 0.0
    epss_score: float = 0.0
    cvss_score: float = 0.0
    exploit_score: float = 0.0
    kev_in_catalog: bool = False
    epss_probability: float = 0.0
    cvss_base: float = 0.0
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    exploit_sources: list[str] = field(default_factory=list)


@dataclass
class TriageResult:
    """Complete triage result for a CVE."""
    cve_id: str
    total_score: int  # 0-100
    severity_label: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    breakdown: TriageBreakdown
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "total_score": self.total_score,
            "severity_label": self.severity_label,
            "breakdown": {
                "kev_score": self.breakdown.kev_score,
                "epss_score": self.breakdown.epss_score,
                "cvss_score": self.breakdown.cvss_score,
                "exploit_score": self.breakdown.exploit_score,
                "kev_in_catalog": self.breakdown.kev_in_catalog,
                "epss_probability": self.breakdown.epss_probability,
                "cvss_base": self.breakdown.cvss_base,
                "exploit_maturity": self.breakdown.exploit_maturity.value,
                "exploit_sources": self.breakdown.exploit_sources,
            },
            "recommendation": self.recommendation,
        }


# Weight constants
WEIGHT_KEV = 35
WEIGHT_EPSS = 25
WEIGHT_CVSS = 25
WEIGHT_EXPLOIT = 15


def compute_triage_score(
    cve_id: str,
    cvss_base: float = 0.0,
    epss_probability: float = 0.0,
    in_kev: bool = False,
    has_exploitdb: bool = False,
    has_github_poc: bool = False,
    has_metasploit: bool = False,
    has_nuclei: bool = False,
    has_vulhub: bool = False,
) -> TriageResult:
    """Compute a deterministic 0-100 triage priority score.

    Args:
        cve_id: CVE identifier.
        cvss_base: CVSS base score (0.0-10.0).
        epss_probability: EPSS probability (0.0-1.0).
        in_kev: Whether the CVE is in CISA KEV catalog.
        has_exploitdb: Whether an ExploitDB entry exists.
        has_github_poc: Whether a GitHub PoC exists.
        has_metasploit: Whether a Metasploit module exists.
        has_nuclei: Whether a Nuclei template exists.
        has_vulhub: Whether a Vulhub environment exists.

    Returns:
        TriageResult with score, severity, and breakdown.
    """
    breakdown = TriageBreakdown()

    # ─── KEV Score (0-35) ─────────────────────────────────────────────
    breakdown.kev_in_catalog = in_kev
    breakdown.kev_score = WEIGHT_KEV if in_kev else 0.0

    # ─── EPSS Score (0-25) ────────────────────────────────────────────
    breakdown.epss_probability = epss_probability
    # Non-linear scaling: higher EPSS scores are weighted more heavily
    if epss_probability >= 0.7:
        epss_factor = 1.0
    elif epss_probability >= 0.3:
        epss_factor = 0.6 + (epss_probability - 0.3) * (0.4 / 0.4)
    elif epss_probability >= 0.1:
        epss_factor = 0.3 + (epss_probability - 0.1) * (0.3 / 0.2)
    else:
        epss_factor = epss_probability / 0.1 * 0.3
    breakdown.epss_score = round(WEIGHT_EPSS * epss_factor, 1)

    # ─── CVSS Score (0-25) ────────────────────────────────────────────
    breakdown.cvss_base = cvss_base
    breakdown.cvss_score = round(WEIGHT_CVSS * (cvss_base / 10.0), 1)

    # ─── Exploit Maturity Score (0-15) ────────────────────────────────
    exploit_sources = []
    if has_exploitdb:
        exploit_sources.append("ExploitDB")
    if has_github_poc:
        exploit_sources.append("GitHub PoC")
    if has_metasploit:
        exploit_sources.append("Metasploit")
    if has_nuclei:
        exploit_sources.append("Nuclei")
    if has_vulhub:
        exploit_sources.append("Vulhub")

    breakdown.exploit_sources = exploit_sources

    # Determine maturity level
    if in_kev:
        maturity = ExploitMaturity.WEAPONIZED
        exploit_factor = 1.0
    elif has_metasploit or (has_exploitdb and has_github_poc):
        maturity = ExploitMaturity.FUNCTIONAL
        exploit_factor = 0.8
    elif has_exploitdb or has_github_poc or has_nuclei:
        maturity = ExploitMaturity.POC
        exploit_factor = 0.5
    elif has_vulhub:
        maturity = ExploitMaturity.UNPROVEN
        exploit_factor = 0.3
    else:
        maturity = ExploitMaturity.NOT_DEFINED
        exploit_factor = 0.0

    breakdown.exploit_maturity = maturity
    breakdown.exploit_score = round(WEIGHT_EXPLOIT * exploit_factor, 1)

    # ─── Total Score ──────────────────────────────────────────────────
    raw_total = (
        breakdown.kev_score
        + breakdown.epss_score
        + breakdown.cvss_score
        + breakdown.exploit_score
    )
    total_score = min(100, max(0, round(raw_total)))

    # ─── Severity Label ───────────────────────────────────────────────
    severity_label = _score_to_severity(total_score)

    # ─── Recommendation ───────────────────────────────────────────────
    recommendation = _generate_recommendation(total_score, breakdown)

    return TriageResult(
        cve_id=cve_id,
        total_score=total_score,
        severity_label=severity_label,
        breakdown=breakdown,
        recommendation=recommendation,
    )


def _score_to_severity(score: int) -> str:
    """Map a 0-100 score to a severity label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"


def _generate_recommendation(score: int, breakdown: TriageBreakdown) -> str:
    """Generate a triage recommendation based on score and breakdown."""
    if breakdown.kev_in_catalog:
        return "IMMEDIATE ACTION: This CVE is actively exploited (CISA KEV). Patch within 24-48 hours."
    elif score >= 80:
        return "URGENT: High-probability exploit with severe impact. Prioritize patching this week."
    elif score >= 60:
        return "HIGH PRIORITY: Significant risk with available exploits. Schedule patching soon."
    elif score >= 40:
        return "MODERATE: Monitor and plan patching in next maintenance window."
    elif score >= 20:
        return "LOW: Limited exploit potential. Address in regular patching cycle."
    else:
        return "INFORMATIONAL: Minimal risk at this time. Monitor for changes."
