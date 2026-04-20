# Step 5: bedrock-assessor

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "모델 선택 (Bedrock)" 섹션
- `/docs/ADR.md` — ADR-002 (Orchestrator-centric, no MCP), ADR-004 (AI는 gate하지 않는다)
- `/docs/PRD.md` — "AI의 역할" 섹션
- `/orchestrator/assessor/interface.py` — RiskAssessor protocol (Step 4)
- `/orchestrator/assessor/static.py` — StaticRiskAssessor (Step 4)
- `/orchestrator/scoring/risk.py` — compute_risk_score (Step 4)
- `/orchestrator/types.py` — RiskReport, Finding, ProductManifest

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 5-1. BedrockRiskAssessor

`orchestrator/assessor/bedrock.py`:

```python
class BedrockRiskAssessor:
    """
    AWS Bedrock (Claude Sonnet)를 사용하는 risk assessor.
    RiskAssessor protocol을 구현한다.

    핵심 규칙:
    - boto3.client("bedrock-runtime")를 사용하여 InvokeModel API 직접 호출.
    - MCP 서버나 Bedrock Agent를 사용하지 않는다 (ADR-002).
    - AI는 narrative와 recommendation만 생성. Gate 결정은 하지 않는다 (ADR-004).
    - Bedrock 호출 실패 시 StaticRiskAssessor로 fallback한다.
    """

    def __init__(
        self,
        controls_repo: ControlsRepository,
        model_id: str = "us.anthropic.claude-sonnet-4-6-20250514-v1:0",
        region: str = "ap-northeast-1",
        fallback: StaticRiskAssessor | None = None
    ): ...

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """
        AI가 product manifest를 분석하여 risk tier를 제안.
        1. manifest를 natural language로 변환
        2. Bedrock에 categorization prompt 전송
        3. 응답에서 risk tier + reasoning 추출
        4. 실패 시 fallback.categorize() 사용
        """
        ...

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str
    ) -> RiskReport:
        """
        AI가 cross-signal reasoning으로 risk report 생성.
        1. compute_risk_score로 deterministic score 계산 (동일)
        2. findings + manifest + controls를 prompt에 포함
        3. Bedrock에 assessment prompt 전송
        4. AI 응답에서 narrative + recommendations 추출
        5. RiskReport에 deterministic score + AI narrative 결합
        6. 실패 시 fallback.assess() 사용
        """
        ...
```

### 5-2. Prompt Templates

`orchestrator/assessor/prompts.py`:

```python
CATEGORIZATION_PROMPT = """
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

ASSESSMENT_PROMPT = """
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
```

### 5-3. Bedrock Client Wrapper

`orchestrator/assessor/bedrock_client.py`:

```python
class BedrockClient:
    """boto3 bedrock-runtime 래퍼. 테스트에서 mock하기 쉽게 분리."""

    def __init__(self, model_id: str, region: str): ...

    def invoke(self, prompt: str, max_tokens: int = 4096) -> str:
        """
        Bedrock InvokeModel API 호출.
        Claude Messages API 형식 사용.
        타임아웃: 30초.
        실패 시 BedrockInvocationError raise.
        """
        ...
```

### 5-4. 테스트

`tests/unit/test_bedrock_assessor.py`:
- `test_categorize_parses_ai_response` — mock BedrockClient가 JSON 응답 반환 → RiskTier 추출 검증
- `test_categorize_fallback_on_failure` — BedrockClient raise → StaticRiskAssessor로 fallback
- `test_categorize_fallback_on_invalid_json` — AI가 잘못된 JSON 반환 → fallback
- `test_assess_combines_score_and_narrative` — deterministic score + AI narrative가 RiskReport에 결합
- `test_assess_fallback_on_failure` — Bedrock 실패 → Static narrative 사용
- `test_assess_uses_deterministic_score` — AI가 다른 score를 제안해도 compute_risk_score의 결과 사용 (AI가 score를 override하지 않음)

`tests/unit/test_prompts.py`:
- `test_categorization_prompt_includes_manifest` — prompt에 product 정보 포함
- `test_assessment_prompt_includes_findings_summary` — prompt에 findings 요약 포함
- `test_assessment_prompt_includes_risk_score` — prompt에 deterministic score 포함

`tests/contract/test_bedrock_client.py`:
- `tests/contract/fixtures/bedrock_categorize_response.json` — 녹화된 Bedrock 응답
- `tests/contract/fixtures/bedrock_assess_response.json` — 녹화된 Bedrock 응답
- `test_invoke_returns_valid_response` — fixture 응답으로 파싱 테스트 (실제 API 미호출)

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make test-contract && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. BedrockRiskAssessor가 RiskAssessor protocol을 구현하는지 확인한다.
3. 모든 테스트가 실제 Bedrock API를 호출하지 않는지 확인한다 (mock/fixture만 사용).
4. CRITICAL 규칙:
   - AI가 risk_score를 override하지 않는지 확인 (deterministic score 유지).
   - AI의 gate_recommendation이 advisory only인지 확인.
   - Bedrock 실패 시 StaticRiskAssessor로 graceful fallback하는지 확인.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- 실제 Bedrock API를 테스트에서 호출하지 마라. 이유: API 비용, 네트워크 의존성, 비결정적 결과.
- AI가 risk score를 계산하거나 override하게 하지 마라. 이유: Score는 compute_risk_score (deterministic). AI는 narrative만.
- AI의 gate_recommendation으로 실제 gate 결정을 하지 마라. 이유: ADR-004. Gate는 ThresholdEvaluator의 책임.
- MCP 서버나 Bedrock Agent를 사용하지 마라. 이유: ADR-002. InvokeModel API만 사용.
