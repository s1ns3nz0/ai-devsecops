"""SP 800-30 risk assessment pipeline with two-stage AI.

4-step process (orchestrator controls every step — ADR-002):

Step 1: GATHER (no AI)
  Collect all context from existing pipeline results.

Step 2: FILTER (Haiku — fast, cheap)
  Filter findings + controls → top critical items.

Step 3: ASSESS (Sonnet — deep reasoning)
  AI follows SP 800-30 methodology:
  threat sources → threat events → likelihood → impact → risk

Step 4: RESPOND (no AI)
  Generate risk responses + POA&M from AI assessment results.

Rules:
- AI is advisory only (ADR-004). Gate decisions are ThresholdEvaluator's job.
- InvokeModel API only (ADR-002). No Bedrock Agent.
- AI failure → StaticRiskAssessmentPipeline fallback.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from orchestrator.assessor.bedrock_client import BedrockClient
from orchestrator.controls.models import Control
from orchestrator.intelligence.models import EnrichedVulnerability
from orchestrator.rmf.models import (
    ImpactAssessment,
    LikelihoodAssessment,
    RiskDetermination,
    RiskResponse,
    SP80030Report,
    ThreatEvent,
    ThreatSource,
)
from orchestrator.types import Finding, ProductManifest

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "very-low": 0}

_TOP_N = 5

FILTER_PROMPT = """\
You are a security analyst triaging findings for a risk assessment.

Product: {product_name} ({tier} tier, {data_classification})
Total findings: {n_findings}
Total controls: {n_controls}

Findings:
{all_findings}

Select the TOP {top_n} most critical findings for deep risk analysis.
Consider: EPSS score, CVSS severity, PCI scope, reachability.

Respond in JSON:
{{"selected_finding_indices": [0, 3, 7, 12, 15], "reasoning": "..."}}
"""

SP800_30_ASSESSMENT_PROMPT = """\
You are a security risk assessor following NIST SP 800-30 Rev 1 methodology.

## Product Context
{architecture_context}
CIA Impact: {cia_levels}

## Critical Findings (filtered)
{filtered_findings}

## Applicable Compliance Controls
{relevant_controls}

## EPSS Exploit Intelligence
{epss_data}

Perform a NIST SP 800-30 risk assessment:

1. THREAT SOURCE IDENTIFICATION (SP 800-30 Section 3.1)
   For each finding, identify the threat source:
   - Type: adversarial / accidental / structural / environmental
   - Capability: very-low / low / moderate / high / very-high
   - Intent and targeting (if adversarial)

2. THREAT EVENT IDENTIFICATION (SP 800-30 Section 3.2)
   Describe the specific threat event:
   - How would the vulnerability be exploited?
   - What ATT&CK technique applies?
   - Is it reachable in this product's code/infrastructure?

3. LIKELIHOOD DETERMINATION (SP 800-30 Section 3.3)
   Using SP 800-30 likelihood scale:
   - Initiation likelihood (how likely threat acts)
   - Impact likelihood (given action, how likely adverse impact)
   - Consider EPSS score as supporting evidence
   - Consider predisposing conditions (internet-facing, PCI scope)

4. IMPACT DETERMINATION (SP 800-30 Section 3.4)
   - Impact on confidentiality, integrity, availability
   - Compliance controls violated
   - Business impact specific to this product

5. RISK DETERMINATION (SP 800-30 Section 3.5)
   - Risk = Likelihood × Impact
   - Use SP 800-30 semi-quantitative scale (1-100)

6. RISK RESPONSE RECOMMENDATION
   - Response type: accept / avoid / mitigate / share / transfer
   - Specific remediation steps
   - Priority and timeline

Respond in JSON matching this schema:
{{
  "executive_summary": "2-3 paragraph summary for decision-makers",
  "threat_sources": [{{
    "id": "TS-XXX-NNN",
    "type": "adversarial|accidental|structural|environmental",
    "name": "...",
    "capability": "very-low|low|moderate|high|very-high",
    "intent": "...",
    "targeting": "..."
  }}],
  "threat_events": [{{
    "id": "TE-NNN",
    "description": "...",
    "source_id": "TS-XXX-NNN",
    "mitre_technique": "TNNNN",
    "relevance": "confirmed|expected|predicted|possible",
    "cve_id": "",
    "target_component": "..."
  }}],
  "likelihood_assessments": [{{
    "initiation_likelihood": "very-low|low|moderate|high|very-high",
    "impact_likelihood": "very-low|low|moderate|high|very-high",
    "overall_likelihood": "very-low|low|moderate|high|very-high",
    "epss_score": null,
    "predisposing_conditions": ["..."],
    "evidence": "..."
  }}],
  "impact_assessments": [{{
    "impact_type": "harm to operations|harm to assets|harm to individuals",
    "cia_impact": {{"confidentiality": "...", "integrity": "...", "availability": "..."}},
    "severity": "very-low|low|moderate|high|very-high",
    "compliance_impact": ["CONTROL-ID"],
    "business_impact": "...",
    "evidence": "..."
  }}],
  "risk_determinations": [{{
    "threat_event_id": "TE-NNN",
    "likelihood": "very-low|low|moderate|high|very-high",
    "impact": "very-low|low|moderate|high|very-high",
    "risk_level": "very-low|low|moderate|high|very-high",
    "risk_score": 0.0
  }}],
  "risk_responses": [{{
    "risk_determination_id": "TE-NNN",
    "response_type": "accept|avoid|mitigate|share|transfer",
    "description": "...",
    "milestones": ["..."],
    "deadline": "YYYY-MM-DD",
    "responsible": "..."
  }}],
  "recommendations": ["..."]
}}
"""


class RiskAssessmentPipeline:
    """SP 800-30 risk assessment pipeline with two-stage AI.

    AI is advisory only (ADR-004). Gate decisions are ThresholdEvaluator's job.
    InvokeModel API only (ADR-002). No Bedrock Agent.
    AI failure → StaticRiskAssessmentPipeline fallback.
    """

    def __init__(
        self,
        bedrock_client: BedrockClient | None = None,
        haiku_model_id: str = "jp.anthropic.claude-haiku-4-5-20251001-v1:0",
    ) -> None:
        self._bedrock = bedrock_client
        self._haiku_model_id = haiku_model_id

    def run(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> SP80030Report:
        """Full SP 800-30 assessment pipeline.

        Falls back to static pipeline on any AI error.
        """
        try:
            gathered = self._step1_gather(
                findings, enriched_vulns, manifest, controls, trigger,
            )
            filtered = self._step2_filter(gathered)
            assessment = self._step3_assess(filtered)
            responses = self._step4_respond(assessment)

            return self._build_report(
                manifest=manifest,
                gathered=gathered,
                assessment=assessment,
                responses=responses,
                mode="ai" if self._bedrock else "static",
            )
        except Exception:
            logger.warning(
                "AI pipeline failed, falling back to static assessment",
                exc_info=True,
            )
            from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline

            return StaticRiskAssessmentPipeline().run(
                findings=findings,
                enriched_vulns=enriched_vulns,
                manifest=manifest,
                controls=controls,
                trigger=trigger,
            )

    def _step1_gather(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> dict[str, Any]:
        """Step 1: GATHER — collect all context (no AI)."""
        findings_data = [
            {
                "index": i,
                "source": f.source,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "control_ids": f.control_ids,
                "package": f.package,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
            }
            for i, f in enumerate(findings)
        ]

        epss_map: dict[str, dict[str, float | str | None]] = {}
        for ev in enriched_vulns:
            epss_map[ev.cve_id] = {
                "epss_score": ev.epss_score,
                "epss_percentile": ev.epss_percentile,
                "priority": ev.priority,
            }

        controls_data = [
            {
                "id": c.id,
                "title": c.title,
                "framework": c.framework,
                "description": c.description,
            }
            for c in controls
        ]

        return {
            "findings": findings_data,
            "epss_map": epss_map,
            "controls": controls_data,
            "manifest": manifest,
            "trigger": trigger,
            "n_findings": len(findings),
            "n_controls": len(controls),
        }

    def _step2_filter(self, gathered: dict[str, Any]) -> dict[str, Any]:
        """Step 2: FILTER — select top-N findings.

        With Bedrock: Haiku selects the most critical findings.
        Without Bedrock: deterministic sort by severity.
        """
        findings = gathered["findings"]

        if self._bedrock and len(findings) > _TOP_N:
            try:
                selected_indices = self._ai_filter(gathered)
                selected = [findings[i] for i in selected_indices if i < len(findings)]
            except Exception:
                logger.warning("AI filter failed, using deterministic fallback", exc_info=True)
                selected = self._deterministic_filter(findings)
        else:
            selected = self._deterministic_filter(findings)

        # Build relevant controls from selected findings
        selected_control_ids: set[str] = set()
        for f in selected:
            selected_control_ids.update(f.get("control_ids", []))

        relevant_controls = [
            c for c in gathered["controls"]
            if c["id"] in selected_control_ids
        ]

        return {
            **gathered,
            "selected_findings": selected,
            "relevant_controls": relevant_controls,
        }

    def _step3_assess(self, filtered: dict[str, Any]) -> dict[str, Any]:
        """Step 3: ASSESS — SP 800-30 structured assessment.

        With Bedrock: Sonnet performs deep reasoning.
        Without Bedrock: static template assessment.
        """
        if self._bedrock:
            return self._ai_assess(filtered)

        return self._static_assess(filtered)

    def _step4_respond(self, assessment: dict[str, Any]) -> list[RiskResponse]:
        """Step 4: RESPOND — generate risk responses (no AI)."""
        raw_responses = assessment.get("risk_responses", [])
        responses: list[RiskResponse] = []
        for r in raw_responses:
            if isinstance(r, RiskResponse):
                responses.append(r)
            elif isinstance(r, dict):
                responses.append(RiskResponse(
                    risk_determination_id=r.get("risk_determination_id", ""),
                    response_type=r.get("response_type", "mitigate"),
                    description=r.get("description", ""),
                    milestones=r.get("milestones", []),
                    deadline=r.get("deadline", ""),
                    responsible=r.get("responsible", "Security Engineer"),
                ))
        return responses

    def _ai_filter(self, gathered: dict[str, Any]) -> list[int]:
        """Call Haiku to select top-N findings."""
        assert self._bedrock is not None

        manifest: ProductManifest = gathered["manifest"]
        findings_text = "\n".join(
            f"[{i}] [{f['severity'].upper()}] {f['source']}: {f['message']} "
            f"({f['file']}:{f['line']}) controls={f['control_ids']}"
            for i, f in enumerate(gathered["findings"])
        )

        prompt = FILTER_PROMPT.format(
            product_name=manifest.name,
            tier="CRITICAL" if "PCI" in manifest.data_classification else "HIGH",
            data_classification=", ".join(manifest.data_classification),
            n_findings=gathered["n_findings"],
            n_controls=gathered["n_controls"],
            all_findings=findings_text,
            top_n=_TOP_N,
        )

        response_text = self._bedrock.invoke(prompt, max_tokens=1024)
        parsed = json.loads(response_text)
        return parsed["selected_finding_indices"]  # type: ignore[no-any-return]

    def _deterministic_filter(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort by severity and return top-N."""
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            reverse=True,
        )
        return sorted_findings[:_TOP_N]

    def _ai_assess(self, filtered: dict[str, Any]) -> dict[str, Any]:
        """Call Sonnet for SP 800-30 structured assessment."""
        assert self._bedrock is not None

        manifest: ProductManifest = filtered["manifest"]

        findings_text = "\n".join(
            f"- [{f['severity'].upper()}] {f['source']}: {f['message']} "
            f"({f['file']}:{f['line']}) controls={f['control_ids']}"
            for f in filtered["selected_findings"]
        )

        controls_text = "\n".join(
            f"- {c['id']}: {c['title']} ({c['framework']})"
            for c in filtered.get("relevant_controls", [])
        )

        epss_text = "\n".join(
            f"- {cve}: EPSS={data.get('epss_score', 'N/A')}, "
            f"priority={data.get('priority', 'N/A')}"
            for cve, data in filtered.get("epss_map", {}).items()
        )

        cia = manifest.impact_levels
        cia_text = (
            f"Confidentiality={cia.get('confidentiality', 'moderate').upper()}, "
            f"Integrity={cia.get('integrity', 'moderate').upper()}, "
            f"Availability={cia.get('availability', 'moderate').upper()}"
        )

        arch_lines = [f"Product: {manifest.name}", f"Description: {manifest.description}"]
        cloud = manifest.deployment.get("cloud", "unknown")
        arch_lines.append(f"Cloud: {cloud}")
        if manifest.jurisdiction:
            arch_lines.append(f"Jurisdiction: {', '.join(manifest.jurisdiction)}")

        prompt = SP800_30_ASSESSMENT_PROMPT.format(
            architecture_context="\n".join(arch_lines),
            cia_levels=cia_text,
            filtered_findings=findings_text or "No findings.",
            relevant_controls=controls_text or "No controls.",
            epss_data=epss_text or "No EPSS data available.",
        )

        response_text = self._bedrock.invoke(prompt, max_tokens=4096)
        return json.loads(response_text)  # type: ignore[no-any-return]

    def _static_assess(self, filtered: dict[str, Any]) -> dict[str, Any]:
        """Deterministic SP 800-30 assessment without AI."""
        from orchestrator.rmf.static_pipeline import StaticRiskAssessmentPipeline

        return StaticRiskAssessmentPipeline.build_assessment(filtered)

    def _build_report(
        self,
        manifest: ProductManifest,
        gathered: dict[str, Any],
        assessment: dict[str, Any],
        responses: list[RiskResponse],
        mode: str,
    ) -> SP80030Report:
        """Assemble SP80030Report from pipeline results."""
        now = datetime.now(tz=timezone.utc)
        report_id = f"RA-SP800-30-{now.strftime('%Y-%m%d')}-001"

        threat_sources = [
            ThreatSource(**ts) if isinstance(ts, dict) else ts
            for ts in assessment.get("threat_sources", [])
        ]
        threat_events = [
            ThreatEvent(**te) if isinstance(te, dict) else te
            for te in assessment.get("threat_events", [])
        ]
        likelihood_assessments = [
            LikelihoodAssessment(**la) if isinstance(la, dict) else la
            for la in assessment.get("likelihood_assessments", [])
        ]
        impact_assessments = [
            ImpactAssessment(**ia) if isinstance(ia, dict) else ia
            for ia in assessment.get("impact_assessments", [])
        ]
        risk_determinations = [
            RiskDetermination(**rd) if isinstance(rd, dict) else rd
            for rd in assessment.get("risk_determinations", [])
        ]

        return SP80030Report(
            report_id=report_id,
            product=manifest.name,
            generated_at=now.isoformat(),
            mode=mode,
            methodology="NIST SP 800-30 Rev 1",
            scope=f"{manifest.name} full stack including IaC and dependencies",
            risk_model="semi-quantitative, threat-oriented",
            assumptions=[
                "All scanners ran successfully",
                "SBOM is complete",
                f"Trigger: {gathered['trigger']}",
            ],
            cia_impact_levels=dict(manifest.impact_levels),
            threat_sources=threat_sources,
            threat_events=threat_events,
            likelihood_assessments=likelihood_assessments,
            impact_assessments=impact_assessments,
            risk_determinations=risk_determinations,
            executive_summary=assessment.get("executive_summary", ""),
            risk_responses=responses,
            recommendations=assessment.get("recommendations", []),
            reassessment_triggers=[
                "New critical CVE in dependency",
                "Architecture change",
                "Compliance framework update",
            ],
            next_review_date=(
                datetime(now.year, now.month + 3 if now.month <= 9 else now.month - 9,
                         now.day, tzinfo=timezone.utc).strftime("%Y-%m-%d")
                if now.month <= 9
                else datetime(now.year + 1, now.month - 9,
                              now.day, tzinfo=timezone.utc).strftime("%Y-%m-%d")
            ),
        )
