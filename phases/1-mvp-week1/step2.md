# Step 2: gate-integration

## 읽어야 할 파일

- `/orchestrator/gate/threshold.py` — YAML threshold evaluator
- `/orchestrator/gate/opa.py` — OPA evaluator (Step 0)
- `/orchestrator/cli.py` — assess command의 gate evaluation 위치
- `/orchestrator/demo.py` — demo의 gate evaluation 위치
- `/orchestrator/types.py` — GateDecision
- `/rego/gates/*.rego` — Step 1에서 생성된 정책 파일

## 작업

### 2-1. Combined Gate Evaluator

`orchestrator/gate/combined.py`를 생성한다:

```python
class CombinedGateEvaluator:
    """Two additive gate layers: YAML thresholds + OPA/Rego.

    Both must pass. YAML is evaluated first (fast path).
    If YAML fails, OPA is skipped (already blocked).
    If YAML passes, OPA evaluates (detailed path).

    핵심 규칙:
    - 두 레이어 모두 통과해야 PASS
    - 두 레이어의 deny 메시지를 합쳐서 reason에 포함
    - OPA 미설치 또는 rego 파일 없으면 YAML만으로 평가
    """

    def __init__(self, threshold_evaluator: ThresholdEvaluator, opa_evaluator: OpaEvaluator | None = None): ...

    def evaluate(self, findings: list[Finding], tier: RiskTier, context: dict | None = None) -> GateDecision:
        """두 레이어로 gate 평가."""
        ...
```

### 2-2. CLI 수정

`orchestrator/cli.py`의 `assess` command에서 `ThresholdEvaluator`를 `CombinedGateEvaluator`로 교체:

```python
# Before:
evaluator = ThresholdEvaluator(profile)
gate = evaluator.evaluate(findings, tier)

# After:
from orchestrator.gate.combined import CombinedGateEvaluator
from orchestrator.gate.opa import OpaEvaluator

threshold_eval = ThresholdEvaluator(profile)
opa_eval = OpaEvaluator(str(_PROJECT_ROOT / "rego" / "gates"))
combined = CombinedGateEvaluator(threshold_eval, opa_eval)

context = {
    "product": product,
    "tier": tier.value,
    "frameworks": profile.frameworks,
    "findings_count": {s: sum(1 for f in findings if f.severity == s) for s in ["critical", "high", "medium", "low"]},
    "pci_scope_count": sum(1 for f in findings if any(c.startswith("PCI-DSS") for c in f.control_ids)),
    "secrets_count": sum(1 for f in findings if f.source == "gitleaks"),
}
gate = combined.evaluate(findings, tier, context)
```

`demo.py`에도 동일하게 적용한다.

### 2-3. CLI 출력 업데이트

Gate 결과 출력에 어떤 레이어가 차단했는지 표시:

```
[3/4] Gate evaluation
      YAML thresholds: BLOCKED — max_critical_findings violated
      OPA/Rego: BLOCKED — Critical finding in PCI scope: CKV_AWS_24
```

또는:

```
[3/4] Gate evaluation
      YAML thresholds: PASSED
      OPA/Rego: PASSED (4 policies evaluated)
```

### 2-4. 테스트

`tests/unit/test_combined_gate.py`:
- `test_both_pass` — YAML pass + OPA pass → PASS
- `test_yaml_fails_opa_skipped` — YAML fail → FAIL (OPA 미평가)
- `test_yaml_passes_opa_fails` — YAML pass + OPA fail → FAIL
- `test_opa_none_yaml_only` — OPA evaluator가 None → YAML만으로 평가
- `test_combined_reason_includes_both` — 두 레이어의 메시지 합산

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 기존 테스트 (135개)가 모두 통과하는지 확인한다.
3. assess command에서 OPA가 없을 때 기존과 동일하게 동작하는지 확인한다.
4. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- ThresholdEvaluator의 기존 로직을 변경하지 마라. CombinedGateEvaluator가 래핑.
- OPA가 없으면 에러를 발생시키지 마라. OPA는 optional 레이어.
- 기존 테스트를 깨뜨리지 마라.
