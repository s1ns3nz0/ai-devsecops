"""Grype scanner wrapper — SCA integration."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


class GrypeScanner:
    """Grype SCA scanner wrapper."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "grype"

    def scan(self, target_path: str) -> list[Finding]:
        """Run grype CLI and parse output."""
        result = subprocess.run(
            ["grype", target_path, "-o", "json"],
            capture_output=True,
            text=True,
        )
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Grype JSON output into Finding objects."""
        data = json.loads(raw_output)
        matches: list[dict[str, object]] = data.get("matches", [])

        findings: list[Finding] = []
        for match in matches:
            vuln = match.get("vulnerability", {})
            assert isinstance(vuln, dict)
            vuln_id = str(vuln.get("id", ""))
            severity = str(vuln.get("severity", "Unknown")).lower()

            artifact = match.get("artifact", {})
            assert isinstance(artifact, dict)
            locations = artifact.get("locations", [])
            assert isinstance(locations, list)
            file_path = ""
            if locations:
                loc = locations[0]
                assert isinstance(loc, dict)
                file_path = str(loc.get("path", ""))

            control_ids = self._control_mapper.map_finding("grype", vuln_id, severity=severity)

            findings.append(
                Finding(
                    source="grype",
                    rule_id=vuln_id,
                    severity=severity,
                    file=file_path,
                    line=0,
                    message=str(vuln.get("description", "")),
                    control_ids=control_ids,
                    product="",
                )
            )

        return findings
