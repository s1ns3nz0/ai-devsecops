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
        """Parse Checkov JSON output into Finding objects.

        Checkov outputs either:
        - A single dict: {"results": {"failed_checks": [...]}} (single framework)
        - A list of dicts: [{"results": ...}, {"results": ...}] (multiple frameworks)
        """
        data = json.loads(raw_output)

        # Normalize to list of result blocks
        if isinstance(data, dict):
            result_blocks = [data]
        elif isinstance(data, list):
            result_blocks = [item for item in data if isinstance(item, dict)]
        else:
            logger.warning("Unexpected Checkov output format: %s", type(data))
            return []

        findings: list[Finding] = []
        for block in result_blocks:
            results = block.get("results", {})
            if not isinstance(results, dict):
                continue

            failed_checks = results.get("failed_checks", [])
            if not isinstance(failed_checks, list):
                continue

            for check in failed_checks:
                if not isinstance(check, dict):
                    continue

                check_id = str(check.get("check_id", ""))
                if not check_id:
                    continue

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
