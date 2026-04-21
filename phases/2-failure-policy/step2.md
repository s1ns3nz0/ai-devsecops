# Step 2: override-mechanism

## 읽어야 할 파일

- `/CLAUDE.md`
- `/orchestrator/resilience/failure.py` — FailureHandler, FailureDecision (Step 1)
- `/orchestrator/evidence/jsonl.py` — JSONL writer (override 기록용)
- `/orchestrator/types.py`

## 작업

### 2-1. Override Record

`orchestrator/resilience/override.py`를 생성한다:

```python
@dataclass
class OverrideRecord:
    """Override 기록 — evidence chain에 포함."""
    id: str                      # OVR-YYYY-MMDD-NNN
    product: str
    tier: str
    failed_scanners: list[str]
    reason: str                  # predefined category
    justification: str           # free text
    approver: str                # who approved (or "force-override" in demo mode)
    timestamp: str               # ISO format
    deferred_scan_sla: str       # SLA deadline ISO timestamp

OVERRIDE_REASONS = [
    "scanner_service_down",
    "scanner_timeout",
    "false_positive_confirmed",
    "emergency_hotfix",
]

class OverrideManager:
    """Override mechanism for high/critical tier scan failures.

    Red Team decisions:
    - Demo: --force-override flag (no approval workflow)
    - Production: integrate with GitHub PR reviews (documented, not built)
    - Override recorded in JSONL for evidence chain
    - SLA: deferred scan must complete within configured hours
    - SLA breach: product risk tier elevated one level

    핵심 규칙:
    - Override는 high/critical tier에서만 사용 가능
    - Override 사유는 predefined categories + free text
    - Override는 항상 JSONL에 기록 (audit trail)
    """

    def __init__(self, jsonl_writer: JsonlWriter): ...

    def create_override(
        self,
        product: str,
        tier: str,
        failed_scanners: list[str],
        reason: str,
        justification: str,
        approver: str = "force-override",
        sla_hours: int = 4,
    ) -> OverrideRecord:
        """
        Override를 생성하고 JSONL에 기록.
        reason은 OVERRIDE_REASONS 중 하나여야 함.
        """
        ...

    def get_pending_overrides(self, product: str | None = None) -> list[OverrideRecord]:
        """
        JSONL에서 deferred scan이 완료되지 않은 override 목록 조회.
        SLA 초과 여부도 포함.
        """
        ...
```

### 2-2. 테스트

`tests/unit/test_override.py`:
- `test_create_override_records_to_jsonl` — JSONL에 기록됨
- `test_override_id_format` — OVR-YYYY-MMDD-NNN 형식
- `test_invalid_reason_raises` — OVERRIDE_REASONS에 없는 사유 → ValueError
- `test_override_has_sla_deadline` — SLA deadline 계산 정확
- `test_get_pending_overrides` — 미완료 override 목록 반환
- `test_override_record_contains_all_fields` — 모든 필드 존재

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. Override가 JSONL에 기록되는지 확인.
3. 결과에 따라 `phases/2-failure-policy/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- GitHub PR review 통합을 구현하지 마라. 이유: demo mode만 (--force-override).
- Background scheduler를 구현하지 마라. 이유: deferred scan은 수동 명령어.
- medium/low tier에서 override를 허용하지 마라. 이유: Red Team RT-25.
