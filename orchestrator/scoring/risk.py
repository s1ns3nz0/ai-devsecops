"""Likelihood × Impact risk scoring — SP 800-30 aligned."""

from __future__ import annotations

from orchestrator.controls.models import Control
from orchestrator.types import Finding, ProductManifest

_DATA_CLASSIFICATION_WEIGHT: dict[str, float] = {
    "PCI": 10.0,
    "PII-FINANCIAL": 8.0,
    "PII-GENERAL": 5.0,
    "PUBLIC": 1.0,
}

_JURISDICTION_WEIGHT: dict[str, float] = {
    "JP": 9.0,  # FISC
    "EU": 7.0,  # GDPR
}
_JURISDICTION_DEFAULT = 3.0

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


def compute_risk_score(
    findings: list[Finding],
    manifest: ProductManifest,
    controls: list[Control],
) -> tuple[float, dict[str, object]]:
    """Likelihood × Impact 기반 risk score 계산.

    Returns:
        (risk_score 0-10, factors dict with evidence per factor)
    """
    # --- Likelihood factors ---
    severity_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        key = f.severity.lower()
        if key in severity_dist:
            severity_dist[key] += 1

    total_findings = len(findings)

    # Weighted severity score (0-10)
    if total_findings > 0:
        weighted = sum(severity_dist[s] * _SEVERITY_WEIGHT[s] for s in severity_dist)
        severity_score = min(weighted / total_findings, 10.0)
        # Scale up with volume — reaches 1.0x at 2 findings, caps at 1.5x
        volume_factor = min(total_findings / 2.0, 1.5)
        severity_score = min(severity_score * volume_factor, 10.0)
    else:
        severity_score = 0.0

    # PCI scope ratio
    pci_findings = sum(
        1 for f in findings if any(cid.startswith("PCI-DSS") for cid in f.control_ids)
    )
    pci_scope_ratio = pci_findings / total_findings if total_findings > 0 else 0.0

    # Secrets detected
    secrets_detected = any(f.source == "gitleaks" for f in findings)
    secrets_bonus = 3.0 if secrets_detected else 0.0

    likelihood_score = min(severity_score + secrets_bonus + pci_scope_ratio, 10.0)

    # --- Impact factors ---
    classifications = {c.upper() for c in manifest.data_classification}
    max_class_weight = max(
        (_DATA_CLASSIFICATION_WEIGHT.get(c, 1.0) for c in classifications),
        default=1.0,
    )

    # Control coverage
    required_control_ids = {c.id for c in controls}
    covered_control_ids = set()
    for f in findings:
        covered_control_ids.update(cid for cid in f.control_ids if cid in required_control_ids)
    control_coverage = (
        len(covered_control_ids) / len(required_control_ids) if required_control_ids else 1.0
    )
    # More coverage of controls with findings = higher impact (more areas affected)
    coverage_impact = control_coverage * 3.0

    # Jurisdiction sensitivity
    jurisdiction_score = max(
        (_JURISDICTION_WEIGHT.get(j.upper(), _JURISDICTION_DEFAULT) for j in manifest.jurisdiction),
        default=_JURISDICTION_DEFAULT,
    )

    impact_score = min(
        (max_class_weight * 0.6 + jurisdiction_score * 0.2 + coverage_impact * 0.2),
        10.0,
    )

    # --- Combined score ---
    risk_score = min(likelihood_score * 0.5 + impact_score * 0.5, 10.0)

    factors = {
        "finding_severity_distribution": severity_dist,
        "pci_scope_ratio": pci_scope_ratio,
        "secrets_detected": secrets_detected,
        "data_classification": sorted(classifications),
        "control_coverage": control_coverage,
        "jurisdiction_sensitivity": jurisdiction_score,
        "likelihood_score": likelihood_score,
        "impact_score": impact_score,
    }

    return risk_score, factors
