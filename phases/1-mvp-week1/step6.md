# Step 6: evidence-defectdojo

## 읽어야 할 파일

- `/orchestrator/evidence/export.py` — 기존 evidence exporter
- `/orchestrator/evidence/jsonl.py` — JSONL reader
- `/orchestrator/integrations/defectdojo.py` — DefectDojo client (Step 5)
- `/orchestrator/cli.py` — assess, export commands
- `/orchestrator/demo.py` — demo flow

## 작업

### 6-1. Evidence Exporter 확장

`orchestrator/evidence/export.py`를 수정하여 DefectDojo를 데이터 소스로 추가:

```python
class EvidenceExporter:
    def __init__(
        self,
        jsonl_reader: JsonlWriter,
        controls_repo: ControlsRepository,
        defectdojo_client: DefectDojoClient | None = None,  # 추가
    ): ...

    def export(self, ...) -> dict:
        """
        데이터 소스 우선순위:
        1. DefectDojo (if available) — source of truth
        2. JSONL (fallback) — always available

        DefectDojo가 사용 가능하면 findings를 DefectDojo에서 조회.
        사용 불가하면 JSONL에서 조회 (기존 동작).
        """
        ...
```

### 6-2. Assess 명령에 DefectDojo sync 추가

`orchestrator/cli.py`의 `assess` command에서 findings를 DefectDojo에 자동 sync:

```python
# After writing to JSONL, optionally sync to DefectDojo
try:
    from orchestrator.integrations.defectdojo import DefectDojoClient
    dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
    dd_key = os.environ.get("DD_API_KEY", "")
    if dd_key:
        dd = DefectDojoClient(base_url=dd_url, api_key=dd_key)
        if dd.health_check():
            product_id = dd.get_or_create_product(product)
            engagement_id = dd.get_or_create_engagement(product_id, f"assess-{trigger}")
            dd.import_findings(engagement_id, findings)
            click.echo(f"      DefectDojo: {len(findings)} findings synced")
except Exception:
    pass  # DefectDojo is optional
```

이 코드는 evidence path — gate 결정 이후에 실행. Gate path에 영향 없음.

### 6-3. Demo 출력 업데이트

Demo에서 DefectDojo 상태 표시:

```
[8/8] Evidence export
      JSONL: output/findings.jsonl (55 entries)
      DefectDojo: synced (if available) or skipped (not configured)
      Report: output/evidence/EVD-2026-0420-001.json
      Coverage: 92.3%
```

### 6-4. README 업데이트

DefectDojo 설정 가이드를 README에 추가:

```markdown
## DefectDojo Integration (Optional)

\```bash
docker compose up -d          # Start DefectDojo
export DD_API_KEY="your-key"  # Get from DefectDojo admin panel
make demo-docker              # Run demo with DefectDojo sync
\```
```

### 6-5. 테스트

`tests/unit/test_evidence_defectdojo.py`:
- `test_export_uses_jsonl_when_no_defectdojo` — DefectDojo 없을 때 기존 동작
- `test_export_prefers_defectdojo_when_available` — DefectDojo mock 사용 시 DefectDojo 데이터 사용
- `test_defectdojo_failure_falls_back_to_jsonl` — DefectDojo 에러 시 JSONL fallback

기존 evidence export 테스트가 모두 통과하는지 확인.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make test-contract && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 기존 테스트 (135+)가 모두 통과하는지 확인한다.
3. DefectDojo 없이 (`DD_API_KEY` 미설정) assess가 기존과 동일하게 동작하는지 확인한다.
4. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- 기존 JSONL 기반 evidence export를 제거하지 마라. JSONL은 항상 백업.
- DefectDojo를 gate 결정에 사용하지 마라. Evidence path only.
- 기존 테스트를 깨뜨리지 마라.
- DD_API_KEY를 코드에 하드코딩하지 마라. 환경변수만.
