# Step 0: opa-engine

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `/orchestrator/gate/threshold.py` — 기존 YAML threshold evaluator
- `/orchestrator/types.py` — GateDecision dataclass
- `/orchestrator/cli.py` — assess command에서 ThresholdEvaluator 사용 위치

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 0-1. OPA Evaluator

`orchestrator/gate/opa.py`를 생성한다:

```python
class OpaEvaluator:
    """OPA/Rego policy evaluator.

    Two additive layers (ADR에서 결정):
    1. YAML thresholds (fast path) — ThresholdEvaluator가 처리
    2. Rego policies (detailed path) — 이 클래스가 처리
    Both must pass for gate to open.

    핵심 규칙:
    - 100% 로컬 (ADR-003). OPA CLI를 subprocess로 호출.
    - AI는 관여하지 않음 (ADR-004).
    - Rego 파일은 rego/gates/ 디렉토리에서 로드.
    """

    def __init__(self, policies_dir: str): ...

    def evaluate(self, findings: list[Finding], context: dict) -> GateDecision:
        """
        모든 .rego 파일을 로드하여 findings에 대해 평가.

        context에는 다음 정보가 포함됨:
        - product: str
        - tier: str (low/medium/high/critical)
        - frameworks: list[str]
        - findings_count: dict (severity별 카운트)
        - pci_scope_count: int
        - secrets_count: int

        OPA 입력 JSON:
        {
          "findings": [...],
          "context": {
            "product": "payment-api",
            "tier": "critical",
            "frameworks": ["pci-dss-4.0", "asvs-5.0-L3"],
            "findings_count": {"critical": 2, "high": 5},
            "pci_scope_count": 3,
            "secrets_count": 1
          }
        }

        OPA 호출: opa eval -i input.json -d {policies_dir} "data.gates.deny"
        deny가 비어있으면 PASS, 아니면 FAIL (deny 메시지를 reason에 포함).
        """
        ...

    def _build_input(self, findings: list[Finding], context: dict) -> dict:
        """OPA 입력 JSON을 생성."""
        ...

    def _run_opa(self, input_json: str, policies_dir: str) -> list[str]:
        """OPA CLI를 실행하고 deny 메시지 목록을 반환."""
        ...
```

### 0-2. OPA 미설치 시 graceful skip

OPA가 설치되어 있지 않으면 (`FileNotFoundError`), 경고를 로깅하고 PASS를 반환한다 (YAML threshold만으로 gate 평가). OPA는 optional layer.

### 0-3. 테스트

`tests/unit/test_opa_evaluator.py`:
- `test_no_rego_files_passes` — rego/gates/가 비어있으면 PASS
- `test_opa_not_installed_passes` — OPA CLI 없을 때 graceful skip + warning
- `test_build_input_format` — 입력 JSON 구조 검증
- `test_deny_messages_in_gate_decision` — deny 메시지가 GateDecision.reason에 포함

OPA CLI를 mock하여 테스트. 실제 OPA 실행은 integration test.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. OPA가 설치되지 않은 환경에서도 테스트가 통과하는지 확인한다.
3. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- OPA CLI를 unit 테스트에서 실행하지 마라. subprocess를 mock하라.
- ThresholdEvaluator를 수정하지 마라. OPA는 별도 레이어다.
- AI를 gate 결정에 사용하지 마라.
