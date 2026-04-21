"""DefectDojo REST API client.

Evidence path only (ADR-003). Gate path is unaffected.
DefectDojo down → gate still works (JSONL is the backup).
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from orchestrator.types import Finding

_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def finding_to_defectdojo(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to DefectDojo Generic Findings Import format.

    hash_code ensures idempotent import (RT-28).
    control_ids are stored as tags for Control ID based querying.
    """
    hash_input = f"{finding.source}:{finding.file}:{finding.line}:{finding.rule_id}"
    hash_code = hashlib.sha256(hash_input.encode()).hexdigest()

    return {
        "title": finding.rule_id,
        "severity": _SEVERITY_MAP.get(finding.severity.lower(), "Info"),
        "description": finding.message,
        "file_path": finding.file,
        "line": finding.line,
        "tags": list(finding.control_ids),
        "hash_code": hash_code,
    }


class DefectDojoClient:
    """DefectDojo REST API client.

    Core rules:
    - Evidence path only (ADR-003). No gate path impact.
    - DefectDojo down → gate works (JSONL backup).
    - Finding hash for idempotent import (RT-28).
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", api_key: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | list[dict[str, Any]] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to DefectDojo API v2."""
        url = f"{self.base_url}/api/v2{path}"
        if params:
            query = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
            url = f"{url}?{query}"

        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", f"Token {self.api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())  # type: ignore[no-any-return]

    def health_check(self) -> bool:
        """Check if DefectDojo is reachable."""
        try:
            url = f"{self.base_url}/api/v2/user_contact_infos/"
            req = urllib.request.Request(url, method="GET")
            req.add_header("Authorization", f"Token {self.api_key}")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return bool(resp.status == 200)
        except (urllib.error.URLError, OSError, TimeoutError):
            return False

    def get_or_create_product(self, name: str, description: str = "") -> int:
        """Find or create a product, return product_id."""
        result = self._request("GET", "/products/", params={"name": name})
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        created = self._request(
            "POST",
            "/products/",
            data={"name": name, "description": description, "prod_type": 1},
        )
        return int(created["id"])

    def get_or_create_engagement(self, product_id: int, name: str) -> int:
        """Find or create an engagement, return engagement_id."""
        result = self._request(
            "GET",
            "/engagements/",
            params={"product": str(product_id), "name": name},
        )
        if result.get("count", 0) > 0:
            return int(result["results"][0]["id"])

        created = self._request(
            "POST",
            "/engagements/",
            data={
                "name": name,
                "product": product_id,
                "target_start": "2020-01-01",
                "target_end": "2099-12-31",
                "engagement_type": "CI/CD",
                "status": "In Progress",
            },
        )
        return int(created["id"])

    def import_findings(
        self,
        engagement_id: int,
        findings: list[Finding],
        scan_type: str = "Generic Findings Import",
    ) -> dict[str, Any]:
        """Import findings to DefectDojo.

        Idempotent: hash_code based dedup (DefectDojo built-in).
        Each finding's control_ids are added as tags.
        """
        dd_findings = [finding_to_defectdojo(f) for f in findings]

        return self._request(
            "POST",
            "/import-scan/",
            data={
                "scan_type": scan_type,
                "engagement": engagement_id,
                "findings": dd_findings,
            },
        )

    def get_findings(
        self, product_name: str, tags: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Get findings for a product. Filter by tags (control_ids)."""
        params: dict[str, str] = {"test__engagement__product__name": product_name}
        if tags:
            params["tags"] = ",".join(tags)

        result = self._request("GET", "/findings/", params=params)
        return list(result.get("results", []))
