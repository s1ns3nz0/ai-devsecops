"""ScannerRunner — executes all scanners and aggregates results."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from orchestrator.types import Finding

if TYPE_CHECKING:
    from orchestrator.scanners.base import Scanner

logger = logging.getLogger(__name__)


class ScannerRunner:
    """모든 scanner를 실행하고 결과를 집계한다."""

    def __init__(self, scanners: list[Scanner]) -> None:
        self._scanners = scanners

    def run_all(self, target_path: str) -> list[Finding]:
        """모든 scanner를 순차 실행.

        각 scanner 실패 시 에러 로깅 후 계속 진행.
        MVP-0 failure policy: log and continue.
        """
        all_findings: list[Finding] = []
        for scanner in self._scanners:
            try:
                findings = scanner.scan(target_path)
                all_findings.extend(findings)
                logger.info("Scanner %s found %d findings", scanner.name, len(findings))
            except Exception:
                logger.exception("Scanner %s failed, continuing with remaining scanners", scanner.name)
        return all_findings
