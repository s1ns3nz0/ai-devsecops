# Step 2: ai-vuln-analyzer

## 읽어야 할 파일

- `/CLAUDE.md` — CRITICAL: AI는 gate하지 않는다
- `/docs/ADR.md` — ADR-002 (Orchestrator-centric), ADR-004 (AI advisory only)
- `/orchestrator/intelligence/models.py` — EnrichedVulnerability (Step 1)
- `/orchestrator/intelligence/enricher.py` — VulnerabilityEnricher (Step 1)
- `/orchestrator/assessor/bedrock_client.py` — BedrockClient
- `/orchestrator/assessor/prompts.py` — 기존 prompt 패턴 참조
- `/orchestrator/assessor/static.py` — StaticRiskAssessor (fallback 패턴 참조)

## 작업

### 2-1. AI Vulnerability Analyzer

`orchestrator/intelligence/analyzer.py`:

```python
@dataclass
class VulnAnalysis:
    """AI-generated vulnerability analysis."""
    cve_id: str
    reachability: str          # "reachable" | "not_reachable" | "unknown"
    attack_scenario: str       # how an attacker would exploit this
    business_impact: str       # impact on the specific product/business
    compliance_impact: list[str]  # which controls are violated
    recommended_action: str    # specific fix instruction
    priority: str              # AI-adjusted priority
    confidence: str            # "high" | "medium" | "low"
    reasoning: str             # AI's full reasoning chain

class VulnAnalyzer:
    """AI-powered vulnerability analysis using Bedrock.

    핵심 규칙:
    - AI는 advisory only (ADR-004). Gate 결정은 ThresholdEvaluator.
    - AI 분석 실패 시 EPSS+CVSS 기반 static 분석으로 fallback.
    - InvokeModel API 직접 호출 (ADR-002).

    AI가 제공하는 가치 (static 분석이 할 수 없는 것):
    1. Reachability — "이 CVE가 당신의 코드에서 실제로 도달 가능한가?"
    2. Attack scenario — "공격자가 어떻게 이 취약점을 악용하는가?"
    3. Business impact — "PCI 결제 API에 미치는 영향은?"
    4. Cross-signal — "다른 findings와 결합했을 때 리스크는?"
    """

    def __init__(self, bedrock_client: BedrockClient | None = None): ...

    def analyze(
        self,
        vuln: EnrichedVulnerability,
        code_context: str = "",       # 관련 소스 코드 snippet (있으면)
        other_findings: list[str] = None,  # 다른 scanner findings 요약
    ) -> VulnAnalysis:
        """
        AI 분석:
        1. EPSS + CVSS + 제품 컨텍스트를 prompt에 포함
        2. Bedrock (Claude Sonnet)에 분석 요청
        3. 응답에서 VulnAnalysis 추출
        4. 실패 시 static fallback

        Static fallback:
        - reachability: "unknown"
        - attack_scenario: CVE description 기반 template
        - priority: EPSS 기반 (enricher의 계산 결과)
        """
        ...

    def analyze_batch(
        self,
        vulns: list[EnrichedVulnerability],
        code_context: str = "",
    ) -> list[VulnAnalysis]:
        """Top-N 취약점만 AI 분석 (비용 절약). 나머지는 static."""
        ...

    def _build_prompt(self, vuln: EnrichedVulnerability, code_context: str, other_findings: list[str] | None) -> str:
        """Build the AI analysis prompt."""
        ...

    def _static_fallback(self, vuln: EnrichedVulnerability) -> VulnAnalysis:
        """EPSS+CVSS 기반 static 분석 (AI 없을 때)."""
        ...
```

### 2-2. Prompt Template

`orchestrator/intelligence/prompts.py`:

```python
VULN_ANALYSIS_PROMPT = """
You are a security analyst performing vulnerability impact analysis.

## Vulnerability
- CVE: {cve_id}
- Package: {package} version {installed_version}
- CVSS Severity: {severity}
- EPSS Score: {epss_score} ({epss_percentile} percentile)

## Product Context
- Product: {product_name}
- Data Classification: {data_classification}
- Deployment: {deployment}

## Code Context (if available)
{code_context}

## Other Findings in This Product
{other_findings}

## Analysis Required
1. REACHABILITY: Is this CVE reachable in this product's code path?
   (reachable / not_reachable / unknown)
2. ATTACK SCENARIO: If exploitable, describe a concrete attack path
   specific to this product. Include attacker prerequisites.
3. BUSINESS IMPACT: What is the impact on this specific product's
   business operations and compliance?
4. COMPLIANCE IMPACT: Which compliance controls (PCI-DSS, ASVS, FISC)
   are violated if exploited?
5. RECOMMENDED ACTION: Specific remediation steps with commands.
6. PRIORITY: critical / high / medium / low (considering EPSS + context)
7. CONFIDENCE: high / medium / low in this analysis

Respond in JSON:
{
  "reachability": "reachable",
  "attack_scenario": "...",
  "business_impact": "...",
  "compliance_impact": ["PCI-DSS-6.3.1", "..."],
  "recommended_action": "pip install cryptography>=41.0.6",
  "priority": "critical",
  "confidence": "high",
  "reasoning": "..."
}
"""
```

### 2-3. 테스트

`tests/unit/test_vuln_analyzer.py`:
- `test_analyze_parses_ai_response` — mock Bedrock 응답 → VulnAnalysis 추출
- `test_analyze_fallback_on_failure` — Bedrock 실패 → static fallback
- `test_analyze_fallback_on_invalid_json` — 잘못된 JSON → static fallback
- `test_static_fallback_uses_epss` — EPSS 기반 priority 결정
- `test_analyze_batch_top_n` — 상위 5개만 AI, 나머지 static
- `test_prompt_includes_product_context` — prompt에 PCI/PII 컨텍스트 포함
- `test_prompt_includes_epss` — prompt에 EPSS score 포함

`tests/contract/fixtures/vuln_analysis_response.json`:
```json
{
  "reachability": "reachable",
  "attack_scenario": "An attacker with network access to the payment API...",
  "business_impact": "Compromise of JWT signing key allows forged payment tokens",
  "compliance_impact": ["PCI-DSS-3.5.1", "PCI-DSS-6.3.1"],
  "recommended_action": "pip install cryptography>=41.0.6",
  "priority": "critical",
  "confidence": "high",
  "reasoning": "CVE-2023-50782 affects Bleichenbacher timing attack in RSA PKCS#1..."
}
```

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make test-contract && make lint
```

## 금지사항

- AI 분석 결과로 gate 결정을 하지 마라. AI는 advisory only (ADR-004).
- 실제 Bedrock API를 unit/contract 테스트에서 호출하지 마라.
- 모든 취약점에 AI를 호출하지 마라. Top-N만 (비용 절약). 나머지는 static fallback.
- MCP나 Bedrock Agent를 사용하지 마라. InvokeModel API만 (ADR-002).
