"""Checkov scanner wrapper — IaC policy gate."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


class CheckovScanner:
    """Checkov IaC scanner wrapper."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "checkov"

    def scan(self, target_path: str) -> list[Finding]:
        """Run checkov CLI and parse output."""
        result = subprocess.run(
            ["checkov", "-d", target_path, "--output", "json", "--quiet"],
            capture_output=True,
            text=True,
        )
        # Checkov returns exit code 1 when findings exist
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Checkov JSON output into Finding objects."""
        data = json.loads(raw_output)
        results = data.get("results", {})
        failed_checks: list[dict[str, object]] = results.get("failed_checks", [])

        findings: list[Finding] = []
        for check in failed_checks:
            check_id = str(check["check_id"])
            severity_raw = check.get("severity")
            severity = str(severity_raw).lower() if severity_raw else "medium"

            line_range = check.get("file_line_range", [0])
            line = int(line_range[0]) if isinstance(line_range, list) and line_range else 0

            control_ids = self._control_mapper.map_finding("checkov", check_id)

            findings.append(
                Finding(
                    source="checkov",
                    rule_id=check_id,
                    severity=severity,
                    file=str(check.get("file_path", "")),
                    line=line,
                    message=str(check.get("check_name", "")),
                    control_ids=control_ids,
                    product="",
                )
            )

        return findings
