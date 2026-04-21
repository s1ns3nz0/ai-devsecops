# Step 3: cli-integration

## 읽어야 할 파일

- `/orchestrator/cli.py` — assess command (현재 flow)
- `/orchestrator/demo.py` — demo flow
- `/orchestrator/resilience/retry.py` — RetryEngine (Step 0)
- `/orchestrator/resilience/failure.py` — FailureHandler (Step 1)
- `/orchestrator/resilience/override.py` — OverrideManager (Step 2)
- `/orchestrator/scanners/runner.py` — ScannerRunner (updated in Step 0)
- `/orchestrator/config/profile.py` — load_profile (failure_policy 포함)

## 작업

### 3-1. Assess Command에 Failure Policy 통합

`orchestrator/cli.py`의 `assess` command를 수정:

```python
# After scanner execution:
# 1. Check RetryResults for failures
# 2. Apply FailureHandler
# 3. If blocked and --force-override: prompt for override
# 4. If blocked without override: exit 1

# New flags:
# --force-override: override a scan failure block (demo mode)
# --override-reason: predefined category (scanner_service_down, etc.)
# --override-justification: free text explanation
```

Flow:
```
Scanners run (with retry) → RetryResults
   ↓
FailureHandler evaluates → FailureDecision
   ↓
If proceed → continue to gate evaluation
If block + --force-override → create override, continue
If block without override → exit 1 with message
   ↓
Gate evaluation (YAML + OPA) → GateDecision
   ↓
Risk assessment → RiskReport
```

### 3-2. CLI 출력 업데이트

```
[2/4] Running scanners
      Checkov: 20 findings (retry: 1/3)
      Semgrep: FAILED after 3 retries (timeout)
      Grype: 16 findings
      Gitleaks: 1 finding

[2.5/4] Failure policy evaluation
      Failed scanners: semgrep
      Tier: critical → policy: block
      Action: BLOCKED — scanner failure in critical tier
      Override: use --force-override --override-reason scanner_timeout

# Or with override:
[2.5/4] Failure policy evaluation
      Failed scanners: semgrep
      Tier: critical → policy: block
      Action: OVERRIDE GRANTED
      Reason: scanner_timeout
      Justification: "Semgrep service outage, will re-scan within 4h"
      SLA deadline: 2026-04-22T18:00:00Z
      Override recorded: OVR-2026-0422-001
```

### 3-3. Status Command

CLI에 `status` command 추가:

```python
@cli.command()
@click.option("--product", default=None)
def status(product: str | None) -> None:
    """Show pending overrides and SLA status."""
    ...
```

출력:
```
$ python -m orchestrator status --product payment-api

Pending overrides:
  OVR-2026-0422-001 | payment-api | scanner_timeout | SLA: 2h remaining

No SLA breaches.
```

### 3-4. Demo 업데이트

`orchestrator/demo.py`에서 failure policy 단계 추가 (scanner 실패 시에만 표시).

### 3-5. ADR 추가

`docs/ADR.md`에 ADR-010 추가:

```
### ADR-010: Failure Policy — Tier-Based Scan Failure Handling
**결정**: Scanner 실패 시 tier별 정책 적용. Critical/High는 fail-closed + override 가능. Medium/Low는 warn-and-proceed.
**이유**: 보안 도구 장애가 개발을 멈추면 안 되지만, 스캔 없이 배포하면 컴플라이언스 위반. Tier별 정책으로 두 문제를 모두 해결.
**트레이드오프**: Override 메커니즘이 남용될 수 있음. Demo 모드에서는 --force-override로 제한. Production에서는 GitHub PR review 통합 필요.
```

### 3-6. 테스트

`tests/unit/test_cli_failure.py`:
- `test_assess_proceeds_when_all_scanners_succeed` — 기존 동작 유지
- `test_assess_blocks_on_scanner_failure_critical_tier` — critical tier + 실패 → exit 1
- `test_assess_warns_on_scanner_failure_medium_tier` — medium tier + 실패 → 계속 진행
- `test_assess_with_force_override` — --force-override → 기록 후 진행
- `test_override_requires_reason` — --force-override without --override-reason → 에러
- `test_status_shows_pending_overrides` — status command 출력

모든 기존 CLI 테스트가 통과하는지 확인.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 기존 assess 테스트가 모두 통과하는지 확인 (하위 호환).
3. `python -m orchestrator --help`에 status command가 표시되는지 확인.
4. 결과에 따라 `phases/2-failure-policy/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- 기존 assess command의 기본 동작을 변경하지 마라. Failure policy는 retry_config가 있을 때만 활성화.
- 기존 테스트를 깨뜨리지 마라.
- AI를 failure 결정에 사용하지 마라.
- Background scheduler를 구현하지 마라. `status` command는 읽기 전용.
