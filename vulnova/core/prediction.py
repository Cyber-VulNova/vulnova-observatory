"""VulNova exploitation-risk score — a transparent, local heuristic.

This is deliberately **not** a black-box ML model and **not** a replacement for
EPSS. EPSS already answers "what is the probability this CVE is exploited in the
next 30 days?" using a trained model. This heuristic layers the operational
signals a triager actually cares about on top of that probability:

    * EPSS probability   — the base predictor (FIRST.org).
    * CISA KEV listing    — confirmed exploited in the wild (the strongest, most
                            certain signal there is).
    * EPSS percentile     — how a CVE ranks relative to all others.
    * CVSS base severity   — impact if exploited (optional).
    * Public exploit code — availability of a working PoC/exploit (optional).

The result is an additive 0–100 "Exploitation Risk" with each factor's exact
point contribution exposed, so the number is always explainable and auditable.
Weights are fixed/bundled (no runtime training) and documented below. Factors
whose data isn't available (e.g. CVSS in a bulk list view) are simply omitted
and reported as such rather than guessed.
"""

from typing import Optional

# Maximum points each factor can contribute. They sum to 100 when every factor
# is available; when optional factors are missing the score is computed on the
# factors present and `max_possible` reflects that.
_W_EPSS = 45.0        # base probability (0-1) → up to 45
_W_KEV = 25.0         # confirmed exploited (CISA KEV) → all-or-nothing
_W_PERCENTILE = 10.0  # relative rank (0-1) → up to 10
_W_CVSS = 12.0        # base severity (score/10) → up to 12
_W_EXPLOIT = 8.0      # public exploit/PoC available → all-or-nothing


def _band(score: float, max_possible: float) -> str:
    """Bucket a score into a qualitative band, normalized to what was scored."""
    pct = (score / max_possible * 100.0) if max_possible else 0.0
    if pct >= 70:
        return "Critical"
    if pct >= 40:
        return "High"
    if pct >= 15:
        return "Moderate"
    return "Low"


def exploitation_risk(
    epss: float,
    percentile: float = 0.0,
    in_kev: bool = False,
    cvss: Optional[float] = None,
    public_exploit: Optional[bool] = None,
) -> dict:
    """Compute the explainable exploitation-risk score for a CVE.

    Args:
        epss: EPSS probability, 0.0–1.0.
        percentile: EPSS percentile, 0.0–1.0.
        in_kev: whether the CVE is in the CISA KEV catalog.
        cvss: CVSS base score 0–10 (optional; omitted from scoring if None).
        public_exploit: whether public exploit code exists (optional).

    Returns:
        {"score": int 0-100, "max_possible": int, "band": str,
         "factors": [{"name", "points", "max", "detail"}]}
    """
    epss = max(0.0, min(1.0, epss or 0.0))
    percentile = max(0.0, min(1.0, percentile or 0.0))

    factors = []
    score = 0.0
    max_possible = 0.0

    # EPSS — always present.
    p = round(epss * _W_EPSS, 1)
    score += p
    max_possible += _W_EPSS
    factors.append({
        "name": "EPSS probability",
        "points": p, "max": _W_EPSS,
        "detail": f"{epss * 100:.1f}% chance of exploitation in 30 days",
    })

    # CISA KEV — always present (boolean).
    kev_pts = _W_KEV if in_kev else 0.0
    score += kev_pts
    max_possible += _W_KEV
    factors.append({
        "name": "CISA KEV",
        "points": kev_pts, "max": _W_KEV,
        "detail": "Confirmed exploited in the wild" if in_kev else "Not in KEV catalog",
    })

    # EPSS percentile — always present.
    pct_pts = round(percentile * _W_PERCENTILE, 1)
    score += pct_pts
    max_possible += _W_PERCENTILE
    factors.append({
        "name": "EPSS percentile",
        "points": pct_pts, "max": _W_PERCENTILE,
        "detail": f"Ranks above {percentile * 100:.0f}% of all CVEs",
    })

    # CVSS severity — optional.
    if cvss is not None and cvss > 0:
        cvss = max(0.0, min(10.0, cvss))
        cvss_pts = round(cvss / 10.0 * _W_CVSS, 1)
        score += cvss_pts
        max_possible += _W_CVSS
        factors.append({
            "name": "CVSS severity",
            "points": cvss_pts, "max": _W_CVSS,
            "detail": f"Base score {cvss:g} (impact if exploited)",
        })

    # Public exploit availability — optional.
    if public_exploit is not None:
        exp_pts = _W_EXPLOIT if public_exploit else 0.0
        score += exp_pts
        max_possible += _W_EXPLOIT
        factors.append({
            "name": "Public exploit",
            "points": exp_pts, "max": _W_EXPLOIT,
            "detail": "Public exploit/PoC available" if public_exploit else "No public exploit found",
        })

    # Normalize to a 0-100 scale against the factors actually scored, so a list
    # view (EPSS+KEV+percentile only) and a full CVE view stay comparable.
    normalized = round(score / max_possible * 100.0, 1) if max_possible else 0.0

    return {
        "score": normalized,
        "raw_points": round(score, 1),
        "max_possible": round(max_possible, 1),
        "band": _band(score, max_possible),
        "factors": factors,
    }
