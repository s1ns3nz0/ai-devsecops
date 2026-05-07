# Step 3: dashboard-exporter

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `orchestrator/rmf/models.py` — SP80030Report dataclass
- `orchestrator/rmf/sar.py` — SecurityAssessmentReport, ControlAssessment dataclasses
- `orchestrator/rmf/poam.py` — POAMItem, AuthorizationDecision dataclasses
- `orchestrator/cli.py` — 현재 `_write_report()` 로직 (lines 575-595)

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`orchestrator/exporters/dashboard.py` 모듈을 새로 생성한다. 파이프라인 결과를 대시보드 최적화된 JSON으로 내보내는 순수 함수.

### 디렉토리 구조

```
orchestrator/exporters/
  __init__.py
  dashboard.py
```

### 시그니처

```python
def export_dashboard(
    report: SP80030Report,
    sar: SecurityAssessmentReport,
    poam_items: list[POAMItem],
    authorization: AuthorizationDecision,
    output_dir: str,
    pipeline_metadata: dict[str, Any] | None = None,
) -> list[str]:
    """Export dashboard-optimized JSON files.

    Writes:
      {output_dir}/dashboard/index.json        — pipeline summary (~2KB)
      {output_dir}/dashboard/sp800-30.json      — full SP 800-30 report
      {output_dir}/dashboard/sar.json            — control assessments
      {output_dir}/dashboard/poam.json           — action items
      {output_dir}/dashboard/authorization.json  — ATO decision

    Returns: list of written file paths.
    """
```

### index.json 스키마

`index.json`은 대시보드 랜딩 뷰에서 사용하는 요약 데이터:

```json
{
  "generated_at": "ISO-8601",
  "product": "payment-api",
  "mode": "ai|static|hybrid",

  "risk_posture": {
    "overall": "high",
    "risk_distribution": {"very-high": 1, "high": 3, "moderate": 1, "low": 0, "very-low": 0},
    "total_findings": 22,
    "assessed_findings": 5
  },

  "gate": {
    "decision": "DATO",
    "reasoning": "...",
    "valid_until": "2026-08-04"
  },

  "sar_summary": {
    "total_controls": 102,
    "satisfied": 38,
    "other_than_satisfied": 31,
    "not_assessed": 33,
    "coverage_pct": 37.3
  },

  "poam_summary": {
    "total_items": 22,
    "by_severity": {"critical": 1, "high": 7, "medium": 10, "low": 4},
    "nearest_deadline": "2026-05-11"
  },

  "pipeline": {
    "scanners": ["semgrep", "grype", "checkov", "gitleaks"],
    "ai_model": "jp.anthropic.claude-sonnet-4-6",
    "duration_seconds": 35.2
  }
}
```

### 상세 JSON 파일

나머지 4개 파일은 해당 dataclass를 `dataclasses.asdict()`로 변환 + JSON 직렬화:

- `sp800-30.json`: `asdict(report)` — threat_sources, events, determinations, executive_summary, recommendations 포함
- `sar.json`: `asdict(sar)` — control_assessments 배열 포함
- `poam.json`: `{"items": [asdict(item) for item in poam_items], "total": len(poam_items)}`
- `authorization.json`: `asdict(authorization)`

### 핵심 규칙

1. **순수 함수**: AI 없음, 네트워크 없음, 부작용은 파일 쓰기만.
2. **JSON 직렬화**: `json.dumps(data, indent=2, default=str, ensure_ascii=False)` — datetime 등 non-serializable은 str 변환.
3. **디렉토리 생성**: `Path(output_dir, "dashboard").mkdir(parents=True, exist_ok=True)`.
4. **index.json 경량화**: 상세 데이터는 포함하지 않는다. 개별 finding, 개별 control assessment 데이터는 상세 파일에만.
5. **pipeline_metadata**: 선택적 dict. scanners 목록, AI 모델 ID, 파이프라인 소요 시간 등 CLI에서 전달.

### 테스트 (TDD)

`tests/unit/test_dashboard_exporter.py`:

1. **test_export_creates_5_files**: output_dir에 dashboard/ 하위 5개 파일 생성 확인 (tmp_path 사용)
2. **test_index_json_under_5kb**: index.json 파일 크기 < 5KB
3. **test_index_contains_risk_posture**: index.json에 risk_distribution, overall 필드 존재
4. **test_index_contains_gate_decision**: gate.decision 필드 == authorization.decision
5. **test_index_contains_sar_summary**: sar_summary.total_controls == sar.total_controls
6. **test_index_contains_poam_summary**: poam_summary.total_items == len(poam_items)
7. **test_sp800_30_json_has_threat_sources**: sp800-30.json에 threat_sources 배열 존재
8. **test_sar_json_has_control_assessments**: sar.json에 control_assessments 배열 존재
9. **test_export_returns_file_paths**: 반환된 경로 리스트가 5개이고 모두 존재

fixture 전략: `SP80030Report`, `SecurityAssessmentReport`, `POAMItem`, `AuthorizationDecision`의 최소 인스턴스를 fixture로 생성.

## Acceptance Criteria

```bash
python -m pytest tests/unit/test_dashboard_exporter.py -v  # 9 tests pass
python -m pytest tests/unit/ -v --tb=short                 # 기존 테스트 깨지지 않음
make lint                                                   # ruff + mypy 통과
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - 네트워크 호출이 없는가? (S3 업로드는 CI의 책임)
   - index.json이 상세 데이터 없이 요약만 포함하는가?
   - 모든 dataclass가 정상적으로 JSON 직렬화되는가?
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다.

## 금지사항

- S3 업로드 코드를 넣지 마라. 이유: 업로드는 GitHub Actions의 책임이다 (step5).
- AI 호출을 넣지 마라. 이유: exporter는 순수 변환 함수다.
- YAML 출력을 이 모듈에 넣지 마라. 이유: YAML 출력은 기존 cli.py `_write_report()`가 담당한다.
- 기존 테스트를 깨뜨리지 마라.
