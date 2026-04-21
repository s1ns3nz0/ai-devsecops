# Step 0: retry-engine

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md`
- `/orchestrator/scanners/runner.py` — 현재 ScannerRunner (log-and-continue)
- `/orchestrator/scanners/base.py` — Scanner protocol
- `/orchestrator/scanners/checkov.py` — subprocess 호출 패턴
- `/orchestrator/types.py` — Finding
- `/controls/products/payment-api/risk-profile.yaml` — failure_policy 설정

## 작업

### 0-1. Retry Engine

`orchestrator/resilience/retry.py`를 생성한다:

```python
class RetryConfig:
    """Retry configuration from risk-profile.yaml failure_policy."""
    max_attempts: int = 3
    backoff_schedule: list[float] = [10.0, 30.0, 60.0]  # seconds
    total_timeout: float = 120.0  # hard cap

class RetryEngine:
    """Scanner retry engine with configurable backoff.

    핵심 규칙:
    - Max 3 attempts per scanner
    - Fixed backoff schedule [10s, 30s, 60s] (not exponential — predictable)
    - Hard cap 120s total per scanner
    - After all retries exhausted, scanner marked as failed
    - Failure handling delegated to FailureHandler (Step 1)
    """

    def __init__(self, config: RetryConfig | None = None): ...

    def execute_with_retry(
        self,
        scanner_name: str,
        scan_fn: Callable[[], list[Finding]],
    ) -> tuple[list[Finding], RetryResult]:
        """
        Execute scan_fn with retry logic.

        Returns:
            (findings, RetryResult) — findings may be empty on failure
        """
        ...
```

```python
@dataclass
class RetryResult:
    """Result of a retry attempt."""
    scanner: str
    success: bool
    attempts: int
    total_time: float
    error_message: str  # empty if success
```

### 0-2. ScannerRunner 업데이트

`orchestrator/scanners/runner.py`를 수정하여 RetryEngine을 사용:

```python
class ScannerRunner:
    def __init__(self, scanners: list[Scanner], retry_config: RetryConfig | None = None): ...

    def run_all(self, target_path: str) -> tuple[list[Finding], list[RetryResult]]:
        """
        모든 scanner를 실행. 실패 시 RetryEngine으로 재시도.
        Returns: (all_findings, retry_results)

        기존 동작과 호환:
        - retry_config가 None이면 RetryEngine 없이 기존 log-and-continue
        - retry_config가 있으면 실패 시 재시도 후 FailureHandler에 위임
        """
        ...
```

### 0-3. 테스트

`tests/unit/test_retry_engine.py`:
- `test_success_on_first_attempt` — 성공 시 재시도 없음, attempts=1
- `test_success_on_second_attempt` — 첫 번째 실패, 두 번째 성공, attempts=2
- `test_all_retries_exhausted` — 3번 모두 실패, success=False, attempts=3
- `test_backoff_schedule_respected` — 재시도 간격이 [10, 30, 60] 준수
- `test_total_timeout_cap` — 120초 초과 시 중단
- `test_retry_result_contains_error` — 실패 시 error_message 포함

`tests/unit/test_scanner_runner_retry.py`:
- `test_runner_without_retry_config` — 기존 동작 유지 (log-and-continue)
- `test_runner_with_retry_config` — 실패 scanner 재시도 후 결과 반환
- `test_runner_returns_retry_results` — RetryResult 목록 반환

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 기존 ScannerRunner 테스트가 여전히 통과하는지 확인 (하위 호환).
3. 결과에 따라 `phases/2-failure-policy/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- time.sleep을 unit 테스트에서 실제로 실행하지 마라. mock하라.
- 기존 ScannerRunner의 인터페이스를 깨뜨리지 마라. retry_config는 optional.
- Gate 결정에 retry 결과를 사용하지 마라. Retry는 scanner 실행 레이어.
