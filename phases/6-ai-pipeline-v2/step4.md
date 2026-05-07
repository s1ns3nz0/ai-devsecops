# Step 4: cli-wiring

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `orchestrator/cli.py` — `risk_assess_cmd` 함수 전체 (특히 lines 475-597)
- `orchestrator/rmf/pipeline.py` — step2에서 수정된 `_assess_findings_parallel()` (progress_callback)
- `orchestrator/exporters/dashboard.py` — step3에서 생성된 exporter

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`orchestrator/cli.py`의 `risk_assess_cmd`를 수정하여:

1. **progress_callback 연결**: parallel pipeline의 `progress_callback`에 click.echo 기반 진행 표시를 연결한다.
2. **dashboard exporter 호출**: 기존 YAML 출력 후, dashboard JSON도 내보낸다.
3. **파이프라인 타이밍 측정**: 전체 파이프라인 소요 시간을 측정하여 pipeline_metadata로 전달.

### 변경 사항

#### 1. Progress callback

`[3/7]` 단계 내에서 per-finding 진행 상황을 표시:

```
[3/7] SP 800-30 Risk Assessment (AI mode — Bedrock)
      Assessing 5 findings in parallel...
      [1/5] TE-001 assessed (ai)
      [2/5] TE-003 assessed (ai)
      [3/5] TE-002 assessed (static — fallback)
      [4/5] TE-004 assessed (ai)
      [5/5] TE-005 assessed (ai)
      Generating executive summary...
      Threat sources: 5 identified
      ...
```

progress_callback 구현:
```python
def _progress(completed: int, total: int, finding_id: str) -> None:
    click.echo(f"      [{completed}/{total}] {finding_id} assessed")
```

이 callback을 `pipeline.run()`에 전달할 수 있도록 `RiskAssessmentPipeline.run()` 시그니처에 `progress_callback` 파라미터를 추가한다 (optional, default None).

#### 2. Dashboard export

`[7/7]` 단계를 `[7/8]`로 바꾸고 `[8/8]`에 dashboard export 추가:

```
[7/8] Reports exported (YAML)
      output/sp800-30-payment-api.yaml
      ...

[8/8] Dashboard exported (JSON)
      output/dashboard/index.json
      output/dashboard/sp800-30.json
      output/dashboard/sar.json
      output/dashboard/poam.json
      output/dashboard/authorization.json
```

#### 3. Pipeline metadata

```python
import time

t0 = time.monotonic()
sp800_report = pipeline.run(...)
duration = time.monotonic() - t0

pipeline_metadata = {
    "scanners": list({f.source for f in findings}),
    "ai_model": model_id or "static",
    "duration_seconds": round(duration, 1),
}
```

### 핵심 규칙

1. **기존 YAML 출력 유지**: dashboard export는 기존 YAML 출력에 추가, 대체가 아니다.
2. **step 번호 변경**: `[7/7]` → `[7/8]`, 새 `[8/8]` 추가. 이전 단계 번호(`[1/7]`~`[6/7]`)도 `[1/8]`~`[6/8]`로 업데이트.
3. **dashboard export 실패 시 무시**: exporter 예외는 잡고 경고만 출력. YAML 출력은 이미 완료되었으므로 RMF 결과물은 보존.
4. **static mode에서도 dashboard 출력**: AI 없이 실행해도 dashboard JSON 생성.

### 테스트 (TDD)

`tests/unit/test_cli_wiring.py` (또는 기존 CLI 테스트 파일에 추가):

1. **test_risk_assess_creates_dashboard_dir**: `risk-assess` 실행 후 `output/dashboard/` 디렉토리 존재 확인
2. **test_risk_assess_creates_index_json**: `output/dashboard/index.json` 생성 확인
3. **test_risk_assess_progress_output**: CLI stdout에 `[1/5]` ... `[5/5]` 패턴 확인 (AI 모드 mock 시)
4. **test_risk_assess_step_numbers_8**: stdout에 `[8/8]` 패턴 확인

mock 전략: `RiskAssessmentPipeline`과 기존 scanner들을 mock. click.testing.CliRunner 사용.

## Acceptance Criteria

```bash
python -m pytest tests/unit/test_cli_wiring.py -v  # 4 tests pass
python -m pytest tests/unit/ -v --tb=short          # 기존 테스트 깨지지 않음
make lint                                            # ruff + mypy 통과
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - 기존 YAML 출력이 그대로 동작하는가?
   - dashboard export 실패가 전체 CLI를 중단시키지 않는가?
   - progress_callback이 AI 모드에서만 동작하고, static 모드에서는 건너뛰는가?
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다.

## 금지사항

- 기존 YAML 출력 로직을 제거하지 마라. 이유: YAML은 Git evidence로 사용된다.
- S3 업로드 코드를 CLI에 넣지 마라. 이유: 업로드는 CI의 책임이다.
- 기존 테스트를 깨뜨리지 마라.
