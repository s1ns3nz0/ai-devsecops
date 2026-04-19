# Step 3: gate-engine

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md` — CRITICAL: AI는 절대 gate 결정을 하지 않는다
- `/docs/ARCHITECTURE.md` — "Gate Path" 섹션, "Gate 결정 흐름"
- `/docs/ADR.md` — ADR-004 (AI는 gate하지 않는다)
- `/orchestrator/types.py` — Finding, GateDecision, RiskProfile
- `/orchestrator/config/profile.py` — load_profile (thresholds 포함)
- `/orchestrator/scanners/` — Scanner wrappers (Step 2)
- `/controls/products/payment-api/risk-profile.yaml`

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 3-1. Threshold Evaluator

`orchestrator/gate/threshold.py`:

```python
class ThresholdEvaluator:
    """
    YAML threshold 기반 gate 평가.
    risk-profile.yaml의 thresholds 섹션을 평가한다.

    핵심 규칙:
    - 이 클래스는 deterministic이다. AI가 관여하지 않는다.
    - Gate path는 100% 로컬이다. 네트워크 호출을 하지 않는다.
    - 모든 threshold는 AND 조건이다. 하나라도 실패하면 FAIL.
    """

    def __init__(self, profile: RiskProfile): ...

    def evaluate(self, findings: list[Finding], tier: RiskTier) -> GateDecision:
        """
        findings를 해당 tier의 threshold와 비교하여 gate 결정을 내린다.

        평가 항목 (risk-profile.yaml thresholds에서 읽음):
        - max_critical_findings: critical severity finding 수 제한
        - max_secrets_detected: secret finding 수 제한
        - max_high_findings_pci: PCI scope의 high finding 수 제한
        - max_high_findings: 전체 high finding 수 제한

        PCI scope 판정: finding.control_ids 중 "PCI-DSS-"로 시작하는 것이 있으면 PCI scope.
        """
        ...
```

### 3-2. Gate Decision 로직

GateDecision에는 다음 정보가 포함된다:
- `passed`: bool — 전체 gate 통과 여부
- `reason`: str — 차단 사유 (어떤 threshold가 실패했는지 구체적으로)
- `threshold_results`: dict — 각 threshold별 {name, limit, actual, passed}
- `findings_count`: dict — severity별 finding 카운트

차단 사유 형식: `"BLOCKED: {threshold_name} violated — found {actual}, limit {limit} (control: {control_id})"`

### 3-3. Integration Test with Scanner Output

`tests/unit/test_gate_engine.py`:
- `test_clean_findings_pass_gate` — finding 없음 → PASS
- `test_critical_finding_blocks` — critical finding 1개 → FAIL (max_critical=0)
- `test_secret_finding_blocks` — gitleaks finding 1개 → FAIL (max_secrets=0)
- `test_high_pci_finding_blocks` — PCI scope high finding → FAIL (max_high_pci=0)
- `test_medium_findings_pass` — medium finding 5개 이하 → PASS
- `test_low_tier_always_passes` — low tier → action: proceed, 항상 PASS
- `test_gate_decision_contains_threshold_details` — GateDecision에 각 threshold 결과 포함

Integration-style test (scanner fixture 활용):
- `test_gate_with_scanner_findings` — Step 2의 scanner fixture로 생성한 Finding 목록을 gate에 통과시킴. risk-profile.yaml의 critical tier threshold 적용. 예상 결과: BLOCKED (critical + secret 존재).

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. CRITICAL 규칙 확인:
   - ThresholdEvaluator에 AI 관련 코드가 없는지 확인한다.
   - 네트워크 호출(requests, urllib, boto3 등)이 없는지 확인한다.
   - Gate 결정이 오직 threshold 비교로만 이루어지는지 확인한다.
3. GateDecision.reason이 사람이 읽을 수 있는 구체적인 정책 참조를 포함하는지 확인한다 (ADR-004).
4. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- AI(Bedrock)를 gate 결정에 사용하지 마라. 이유: ADR-004. "왜 차단되었나?"의 답은 정책 참조여야 한다.
- OPA/Rego를 이 step에서 구현하지 마라. 이유: OPA는 MVP tier에서 추가된다. MVP-0는 YAML threshold만 사용한다.
- 네트워크 호출을 하지 마라. 이유: Gate path는 100% 로컬이다 (ADR-003).
- `warn_and_proceed` 로직을 구현하지 마라. 이유: MVP-0는 `block` 또는 `proceed`만 지원한다. warn은 MVP tier에서 추가.
