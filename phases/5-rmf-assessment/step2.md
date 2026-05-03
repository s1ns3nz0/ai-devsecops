# Step 2: ai-risk-pipeline

## 읽어야 할 파일

- `/CLAUDE.md` — CRITICAL: AI는 gate 결정하지 않음
- `/docs/ADR.md` — ADR-002 (orchestrator-centric), ADR-004 (AI advisory only)
- `/orchestrator/rmf/models.py` — Step 1의 SP 800-30 모델
- `/orchestrator/assessor/bedrock_client.py` — BedrockClient
- `/orchestrator/assessor/prompts.py` — 기존 prompt 패턴
- `/orchestrator/intelligence/enricher.py` — EnrichedVulnerability
- `/orchestrator/types.py` — ProductManifest (with CIA impact_levels)

## 작업

### 2-1. Two-Stage AI Pipeline

`orchestrator/rmf/pipeline.py`를 생성한다:

```python
class RiskAssessmentPipeline:
    """SP 800-30 risk assessment pipeline.

    4-step process (orchestrator controls every step — ADR-002):

    Step 1: GATHER (no AI)
      Collect all context from existing pipeline results.

    Step 2: FILTER (Haiku — fast, cheap)
      Filter 22 findings + 102 controls → top critical items.

    Step 3: ASSESS (Sonnet — deep reasoning)
      AI follows SP 800-30 methodology:
      threat sources → threat events → likelihood → impact → risk

    Step 4: RESPOND (no AI)
      Generate risk responses + POA&M from AI assessment results.

    핵심 규칙:
    - AI는 advisory only (ADR-004). Gate 결정은 ThresholdEvaluator.
    - InvokeModel API만 (ADR-002). No Bedrock Agent.
    - AI 실패 시 StaticRiskAssessmentPipeline으로 fallback.
    """

    def __init__(
        self,
        bedrock_client: BedrockClient | None = None,
        haiku_model_id: str = "jp.anthropic.claude-haiku-4-5-20251001-v1:0",
    ): ...

    def run(
        self,
        findings: list[Finding],
        enriched_vulns: list[EnrichedVulnerability],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str,
    ) -> SP80030Report:
        """Full SP 800-30 assessment pipeline."""
        ...

    def _step1_gather(self, ...) -> dict[str, object]:
        """Collect all context into a structured input."""
        ...

    def _step2_filter(self, gathered: dict, ...) -> dict[str, object]:
        """Haiku filters to top-N findings + relevant controls.
        If no Bedrock: return top-N by severity (deterministic).
        """
        ...

    def _step3_assess(self, filtered: dict, ...) -> dict[str, object]:
        """Sonnet performs SP 800-30 structured assessment.
        If no Bedrock: use static templates.
        """
        ...

    def _step4_respond(self, assessment: dict, ...) -> list[RiskResponse]:
        """Generate risk responses from assessment (no AI)."""
        ...
```

### 2-2. Haiku Filter Prompt (Step 2)

```python
FILTER_PROMPT = """
You are a security analyst triaging findings for a risk assessment.

Product: {product_name} ({tier} tier, {data_classification})
Total findings: {n_findings}
Total controls: {n_controls}

Findings:
{all_findings}

Select the TOP 5 most critical findings for deep risk analysis.
Consider: EPSS score, CVSS severity, PCI scope, reachability.

Respond in JSON:
{{"selected_finding_indices": [0, 3, 7, 12, 15], "reasoning": "..."}}
"""
```

### 2-3. Sonnet Assessment Prompt (Step 3)

```python
SP800_30_ASSESSMENT_PROMPT = """
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
  "threat_sources": [...],
  "threat_events": [...],
  "likelihood_assessments": [...],
  "impact_assessments": [...],
  "risk_determinations": [...],
  "risk_responses": [...],
  "recommendations": [...]
}}
"""
```

### 2-4. Static Fallback Pipeline

`orchestrator/rmf/static_pipeline.py`:

```python
class StaticRiskAssessmentPipeline:
    """SP 800-30 assessment without AI.

    Uses deterministic logic + templates when Bedrock is unavailable.
    Same SP80030Report output format — just less nuanced.
    """

    def run(self, ...) -> SP80030Report:
        """Template-based SP 800-30 assessment."""
        ...
```

### 2-5. 테스트

`tests/unit/test_risk_pipeline.py`:
- `test_pipeline_produces_sp800_30_report` — 전체 보고서 생성
- `test_pipeline_static_fallback` — Bedrock 없을 때 static 생성
- `test_filter_step_selects_top_n` — 상위 N개 findings 선택
- `test_assess_follows_sp800_30_structure` — 보고서에 5단계 포함
- `test_risk_determination_uses_likelihood_x_impact` — 리스크 = L × I
- `test_ai_response_parsed_to_models` — AI JSON → SP800-30 dataclasses

Bedrock 호출은 mock. 실제 API 미호출.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- AI 결과를 gate 결정에 사용하지 마라 (ADR-004).
- Bedrock Agent나 MCP를 사용하지 마라 (ADR-002). InvokeModel만.
- 실제 Bedrock API를 unit 테스트에서 호출하지 마라.
- AI 호출 실패 시 반드시 static fallback 제공.
