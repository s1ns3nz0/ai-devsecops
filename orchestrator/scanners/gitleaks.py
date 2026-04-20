"""Gitleaks scanner wrapper — secrets scanning."""

from __future__ import annotations

import json
import logging
import subprocess

from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.types import Finding

logger = logging.getLogger(__name__)


class GitleaksScanner:
    """Gitleaks secrets scanner wrapper."""

    def __init__(self, control_mapper: ControlMapper) -> None:
        self._control_mapper = control_mapper

    @property
    def name(self) -> str:
        return "gitleaks"

    def scan(self, target_path: str) -> list[Finding]:
        """Run gitleaks CLI and parse output."""
        result = subprocess.run(
            ["gitleaks", "detect", "--source", target_path, "--report-format", "json", "--report-path", "-"],
            capture_output=True,
            text=True,
        )
        # Gitleaks returns exit code 1 when findings exist
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse Gitleaks JSON output into Finding objects."""
        data = json.loads(raw_output)
        if not isinstance(data, list):
            return []

        findings: list[Finding] = []
        for leak in data:
            rule_id = str(leak.get("RuleID", ""))
            control_ids = self._control_mapper.map_finding("gitleaks", rule_id)

            findings.append(
                Finding(
                    source="gitleaks",
                    rule_id=rule_id,
                    severity="critical",
                    file=str(leak.get("File", "")),
                    line=int(leak.get("StartLine", 0)),
                    message=str(leak.get("Description", "")),
                    control_ids=control_ids,
                    product="",
                )
            )

        return findings
