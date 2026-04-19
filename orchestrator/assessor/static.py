"""StaticRiskAssessor — deterministic risk assessment without AI (ADR-004)."""

from __future__ import annotations

import itertools
from datetime import datetime, timezone

from orchestrator.controls.models import Control
from orchestrator.scoring.risk import compute_risk_score
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier

_REPORT_COUNTER = itertools.count(1)


def _generate_report_id() -> str:
    """RA-YYYY-MMDD-NNN 형식의 report ID 생성."""
    now = datetime.now(tz=timezone.utc)
    seq = next(_REPORT_COUNTER)
    return f"RA-{now.year}-{now.month:02d}{now.day:02d}-{seq:03d}"


def _score_to_label(score: float) -> str:
    if score >= 8.0:
        return "very-high"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "very-low"


def _gate_recommendation(score: float) -> str:
    if score >= 7.0:
        return "BLOCK"
    if score >= 4.0:
        return "REVIEW"
    return "PROCEED"


class StaticRiskAssessor:
    """AI 없이 동작하는 risk assessor. Deterministic 로직만 사용한다."""

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """Categorization 규칙 (deterministic)."""
        classifications = {c.upper() for c in manifest.data_classification}
        jurisdictions = {j.upper() for j in manifest.jurisdiction}

        has_pci = "PCI" in classifications
        has_pii_financial = "PII-FINANCIAL" in classifications
        has_jp = "JP" in jurisdictions

        if has_pci and has_jp:
            return RiskTier.CRITICAL
        if has_pci:
            return RiskTier.HIGH
        if has_pii_financial:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> RiskReport:
        """Static assessment: compute_risk_score + 템플릿 narrative."""
        score, factors = compute_risk_score(findings, manifest, controls)

        severity_dist = factors["finding_severity_distribution"]
        affected_controls = sorted(
            {cid for f in findings for cid in f.control_ids}
        )

        narrative = (
            f"Risk Assessment for {manifest.name}: {trigger} trigger. "
            f"Found {severity_dist['critical']} critical, {severity_dist['high']} high "
            f"findings across {len(controls)} controls. "
            f"Data classification: {', '.join(sorted(manifest.data_classification))}. "
            f"Risk score: {score:.1f}/10. "
            f"Gate recommendation: {_gate_recommendation(score)}."
        )

        return RiskReport(
            id=_generate_report_id(),
            trigger=trigger,
            product=manifest.name,
            risk_tier=self.categorize(manifest),
            likelihood=_score_to_label(factors["likelihood_score"]),
            impact=_score_to_label(factors["impact_score"]),
            risk_score=score,
            narrative=narrative,
            findings_summary=severity_dist,
            affected_controls=affected_controls,
            gate_recommendation=_gate_recommendation(score),
        )
