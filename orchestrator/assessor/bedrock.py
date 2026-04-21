"""BedrockRiskAssessor — AI-powered risk assessment via AWS Bedrock (ADR-002, ADR-004)."""

from __future__ import annotations

import itertools
import json
import logging
from datetime import datetime, timezone

from orchestrator.assessor.bedrock_client import BedrockClient, BedrockInvocationError
from orchestrator.assessor.prompts import build_assessment_prompt, build_categorization_prompt
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.controls.models import Control
from orchestrator.scoring.risk import compute_risk_score
from orchestrator.types import Finding, ProductManifest, RiskReport, RiskTier

logger = logging.getLogger(__name__)

_REPORT_COUNTER = itertools.count(1)

_VALID_TIERS = {t.value for t in RiskTier}


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


class BedrockRiskAssessor:
    """AWS Bedrock (Claude Sonnet)를 사용하는 risk assessor.

    RiskAssessor protocol을 구현한다.

    핵심 규칙:
    - boto3.client("bedrock-runtime")를 사용하여 InvokeModel API 직접 호출.
    - MCP 서버나 Bedrock Agent를 사용하지 않는다 (ADR-002).
    - AI는 narrative와 recommendation만 생성. Gate 결정은 하지 않는다 (ADR-004).
    - Bedrock 호출 실패 시 StaticRiskAssessor로 fallback한다.
    """

    def __init__(
        self,
        client: BedrockClient,
        fallback: StaticRiskAssessor | None = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or StaticRiskAssessor()

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """AI가 product manifest를 분석하여 risk tier를 제안.

        1. manifest를 natural language로 변환
        2. Bedrock에 categorization prompt 전송
        3. 응답에서 risk tier + reasoning 추출
        4. 실패 시 fallback.categorize() 사용
        """
        try:
            prompt = build_categorization_prompt(manifest)
            raw = self._client.invoke(prompt)
            data = json.loads(raw)
            tier_str = data["tier"].lower()
            if tier_str not in _VALID_TIERS:
                raise ValueError(f"Invalid tier: {tier_str}")
            return RiskTier(tier_str)
        except (BedrockInvocationError, json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning("Bedrock categorize failed, falling back to static: %s", exc)
            return self._fallback.categorize(manifest)

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> RiskReport:
        """AI가 cross-signal reasoning으로 risk report 생성.

        1. compute_risk_score로 deterministic score 계산 (동일)
        2. findings + manifest + controls를 prompt에 포함
        3. Bedrock에 assessment prompt 전송
        4. AI 응답에서 narrative + recommendations 추출
        5. RiskReport에 deterministic score + AI narrative 결합
        6. 실패 시 fallback.assess() 사용

        CRITICAL: AI가 risk_score를 override하지 않는다. Score는 항상 compute_risk_score 결과.
        CRITICAL: gate_recommendation은 advisory only (ADR-004).
        """
        # Deterministic scoring — always used regardless of AI
        score, factors = compute_risk_score(findings, manifest, controls)
        severity_dist: dict[str, int] = factors["finding_severity_distribution"]  # type: ignore[assignment]
        likelihood_score = float(factors["likelihood_score"])  # type: ignore[arg-type]
        impact_score = float(factors["impact_score"])  # type: ignore[arg-type]
        affected_controls = sorted({cid for f in findings for cid in f.control_ids})
        risk_tier = self._fallback.categorize(manifest)

        try:
            # AI categorization for tier
            risk_tier = self.categorize(manifest)

            prompt = build_assessment_prompt(
                manifest=manifest,
                findings=findings,
                controls=controls,
                risk_tier=risk_tier,
                risk_score=score,
                trigger=trigger,
            )
            raw = self._client.invoke(prompt)
            data = json.loads(raw)

            narrative = data["narrative"]
            gate_rec = data.get("gate_recommendation", "proceed")
            insights = data.get("cross_signal_insights", [])
            recs = data.get("recommendations", [])

            return RiskReport(
                id=_generate_report_id(),
                trigger=trigger,
                product=manifest.name,
                risk_tier=risk_tier,
                likelihood=_score_to_label(likelihood_score),
                impact=_score_to_label(impact_score),
                risk_score=score,  # Deterministic — AI cannot override
                narrative=narrative,
                findings_summary=severity_dist,
                affected_controls=affected_controls,
                gate_recommendation=gate_rec,
                cross_signal_insights=insights,
                recommendations=recs,
            )
        except (BedrockInvocationError, json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning("Bedrock assess failed, falling back to static: %s", exc)
            return self._fallback.assess(findings, manifest, controls, trigger)
