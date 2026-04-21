# Step 1: failure-handler

## 읽어야 할 파일

- `/CLAUDE.md`
- `/orchestrator/resilience/retry.py` — Step 0에서 생성된 RetryEngine, RetryResult
- `/orchestrator/types.py` — RiskTier, RiskProfile
- `/orchestrator/gate/combined.py` — CombinedGateEvaluator
- `/controls/products/payment-api/risk-profile.yaml` — failure_policy 섹션

## 작업

### 1-1. Failure Handler

`orchestrator/resilience/failure.py`를 생성한다:

```python
@dataclass
class FailureDecision:
    """Failure handler의 결정."""
    action: str           # "block" | "warn_and_proceed"
    reason: str
    failed_scanners: list[str]
    tier: str
    override_available: bool  # True if tier is high/critical

class FailureHandler:
    """Scanner failure에 대한 tier별 정책 처리.

    Red Team RT-23에서 결정된 정책:
    - Critical/High: fail-closed (block). Override 가능.
    - Medium/Low: warn_and_proceed. Override 불필요.

    핵심 규칙:
    - Gate path에 영향. Scanner 실패 시 gate가 block할 수 있음.
    - 하지만 AI가 결정하는 것이 아님 — failure_policy가 결정 (deterministic).
    """

    def __init__(self, profile: RiskProfile): ...

    def handle(self, retry_results: list[RetryResult], tier: RiskTier) -> FailureDecision:
        """
        실패한 scanner에 대해 tier별 failure_policy 적용.

        1. retry_results에서 실패한 scanner 추출
        2. risk-profile.yaml의 failure_policy[tier] 조회
        3. scan_failure: "block" → FailureDecision(action="block")
        4. scan_failure: "proceed" → FailureDecision(action="warn_and_proceed")
        5. 모든 scanner 성공 → FailureDecision(action="proceed", no failures)
        """
        ...
```

### 1-2. 테스트

`tests/unit/test_failure_handler.py`:
- `test_no_failures_proceeds` — 모든 scanner 성공 → proceed
- `test_critical_tier_blocks_on_failure` — critical tier + scanner 실패 → block
- `test_high_tier_blocks_on_failure` — high tier + scanner 실패 → block
- `test_medium_tier_warns_on_failure` — medium tier + scanner 실패 → warn_and_proceed
- `test_low_tier_warns_on_failure` — low tier + scanner 실패 → warn_and_proceed
- `test_override_available_for_critical` — critical tier → override_available=True
- `test_override_not_available_for_medium` — medium tier → override_available=False
- `test_failure_decision_lists_failed_scanners` — 실패한 scanner 이름 목록 포함

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. failure_policy가 risk-profile.yaml에서 읽히는지 확인.
3. 결과에 따라 `phases/2-failure-policy/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- AI를 failure 결정에 사용하지 마라. failure_policy는 deterministic.
- Gate 결정을 직접 수정하지 마라. FailureHandler는 advisory — Step 3에서 CLI가 통합.
- 기존 gate 테스트를 깨뜨리지 마라.
