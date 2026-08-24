"""Local-AI Briefing - offline triage summaries via local LLM.

Uses Ollama (or compatible API) to generate plain-language triage
briefings from CVE data. Fully offline - no data leaves the machine.

Supported LLM backends:
- Ollama (default, http://localhost:11434)
- Any OpenAI-compatible API endpoint
"""

from typing import Optional

import httpx

from vulnova.core.config import Config


TRIAGE_PROMPT_TEMPLATE = """You are a cybersecurity analyst writing a triage briefing for your team.
Given the following vulnerability data, write a clear, actionable 2-3 paragraph briefing.

Include:
1. What the vulnerability is and what it affects
2. How severe it is and why (cite CVSS, EPSS, KEV status)
3. Whether exploits are publicly available
4. Recommended immediate actions

Vulnerability Data:
- CVE ID: {cve_id}
- Description: {description}
- CVSS Score: {cvss_score} ({severity})
- EPSS Score: {epss_score}% probability of exploitation in next 30 days
- CISA KEV: {kev_status}
- Triage Priority Score: {triage_score}/100 ({triage_label})
- Known Exploits: {exploits}
- Affected Products: {products}

Write the briefing in plain language a security team lead can act on immediately.
Keep it concise but complete. No markdown formatting."""


class LLMClient:
    """Client for local LLM inference (Ollama-compatible)."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.endpoint = self.config.llm_endpoint
        self.model = self.config.llm_model

    def is_available(self) -> bool:
        """Check if the local LLM is reachable and ready."""
        try:
            resp = httpx.get(f"{self.endpoint}/api/tags", timeout=5.0)
            return resp.status_code == 200
        except (httpx.HTTPError, Exception):
            return False

    def list_models(self) -> list[str]:
        """List available models on the local Ollama instance."""
        try:
            resp = httpx.get(f"{self.endpoint}/api/tags", timeout=5.0)
            resp.raise_for_status()
            data = resp.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except (httpx.HTTPError, Exception):
            return []

    def generate_briefing(
        self,
        cve_id: str,
        description: str = "",
        cvss_score: float = 0.0,
        severity: str = "NONE",
        epss_score: float = 0.0,
        kev_status: str = "Not in KEV",
        triage_score: int = 0,
        triage_label: str = "INFO",
        exploits: str = "None known",
        products: str = "Unknown",
    ) -> Optional[str]:
        """Generate a triage briefing using the local LLM.

        Args:
            cve_id: CVE identifier.
            description: CVE description text.
            cvss_score: CVSS base score.
            severity: Severity label.
            epss_score: EPSS percentage.
            kev_status: KEV catalog status.
            triage_score: VulNova triage score (0-100).
            triage_label: Triage severity label.
            exploits: Summary of available exploits.
            products: Affected products.

        Returns:
            Generated briefing text or None if LLM is unavailable.
        """
        prompt = TRIAGE_PROMPT_TEMPLATE.format(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            epss_score=epss_score,
            kev_status=kev_status,
            triage_score=triage_score,
            triage_label=triage_label,
            exploits=exploits,
            products=products,
        )

        try:
            resp = httpx.post(
                f"{self.endpoint}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 500,
                    },
                },
                timeout=120.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except (httpx.HTTPError, Exception) as e:
            return None

    def generate_raw(self, prompt: str) -> Optional[str]:
        """Send a raw prompt to the LLM.

        Args:
            prompt: The prompt text.

        Returns:
            Generated response or None.
        """
        try:
            resp = httpx.post(
                f"{self.endpoint}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=120.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except (httpx.HTTPError, Exception):
            return None
