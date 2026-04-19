"""Prompt templates for Bedrock risk assessment."""

from __future__ import annotations

from orchestrator.controls.models import Control
from orchestrator.types import Finding, ProductManifest, RiskTier

CATEGORIZATION_PROMPT = """\
You are a security risk assessor. Analyze this product and determine the risk tier.

Product: {name}
Description: {description}
Data classification: {data_classification}
Jurisdiction: {jurisdiction}
Deployment: {deployment}

Risk tier definitions:
- LOW: No sensitive data, internal tools
- MEDIUM: PII or moderate sensitivity
- HIGH: PCI cardholder data, financial data
- CRITICAL: PCI + regulated jurisdiction (JP/FISC)

Respond in JSON:
{{"tier": "high", "reasoning": "...", "threat_profile": ["T1190", "T1078"]}}
"""

ASSESSMENT_PROMPT = """\
You are a security risk assessor performing cross-signal analysis.

Product: {product_name} (Risk tier: {tier})
Trigger: {trigger}
Data classification: {data_classification}

Findings ({n_findings} total):
{findings_summary}

Applicable controls ({n_controls}):
{controls_summary}

Risk score (deterministic): {risk_score}/10

Provide:
1. A 2-3 paragraph narrative explaining the risk in auditor-appropriate language
2. Cross-signal insights (connections between findings that individual scanners miss)
3. Recommendations for remediation
4. Gate recommendation: proceed / hold_for_review / block (advisory only)

Respond in JSON:
{{"narrative": "...", "cross_signal_insights": [...], "recommendations": [...], "gate_recommendation": "..."}}
"""


def _format_findings_summary(findings: list[Finding]) -> str:
    lines: list[str] = []
    for f in findings:
        controls = ", ".join(f.control_ids) if f.control_ids else "unmapped"
        lines.append(f"- [{f.severity.upper()}] {f.source}: {f.message} ({f.file}:{f.line}) → {controls}")
    return "\n".join(lines) if lines else "No findings."


def _format_controls_summary(controls: list[Control]) -> str:
    lines: list[str] = []
    for c in controls:
        lines.append(f"- {c.id}: {c.title} ({c.framework})")
    return "\n".join(lines) if lines else "No controls."


def build_categorization_prompt(manifest: ProductManifest) -> str:
    """Build categorization prompt from product manifest."""
    return CATEGORIZATION_PROMPT.format(
        name=manifest.name,
        description=manifest.description,
        data_classification=", ".join(manifest.data_classification),
        jurisdiction=", ".join(manifest.jurisdiction),
        deployment=", ".join(f"{k}={v}" for k, v in manifest.deployment.items()),
    )


def build_assessment_prompt(
    *,
    manifest: ProductManifest,
    findings: list[Finding],
    controls: list[Control],
    risk_tier: RiskTier,
    risk_score: float,
    trigger: str,
) -> str:
    """Build assessment prompt from findings, controls, and context."""
    return ASSESSMENT_PROMPT.format(
        product_name=manifest.name,
        tier=risk_tier.value,
        trigger=trigger,
        data_classification=", ".join(manifest.data_classification),
        n_findings=len(findings),
        findings_summary=_format_findings_summary(findings),
        n_controls=len(controls),
        controls_summary=_format_controls_summary(controls),
        risk_score=risk_score,
    )
