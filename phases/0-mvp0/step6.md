# Step 6: evidence-export

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "Evidence Path" 섹션, "데이터 흐름"
- `/docs/ADR.md` — ADR-008 (Evidence는 generated artifact)
- `/docs/PRD.md` — "Evidence Export" 관련
- `/orchestrator/types.py` — Finding, RiskReport
- `/orchestrator/controls/repository.py` — ControlsRepository
- `/orchestrator/controls/models.py` — Control

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 6-1. JSONL Writer

`orchestrator/evidence/jsonl.py`:

```python
class JsonlWriter:
    """
    Append-only JSONL 파일 writer.

    핵심 규칙:
    - 항상 로컬 파일에 쓴다 (네트워크 X).
    - 각 엔트리에 timestamp, finding hash 포함.
    - Finding hash = hash(source + file + line + rule_id + commit_sha)
    - 이 파일은 DefectDojo 백업 + 디버그 로그 + evidence source.
    """

    def __init__(self, output_path: str): ...

    def write_finding(self, finding: Finding, commit_sha: str = "") -> None:
        """단일 finding을 JSONL에 append."""
        ...

    def write_findings(self, findings: list[Finding], commit_sha: str = "") -> None:
        """여러 findings를 JSONL에 append."""
        ...

    def write_risk_report(self, report: RiskReport) -> None:
        """risk report를 JSONL에 append."""
        ...

    def write_gate_decision(self, decision: GateDecision, product: str) -> None:
        """gate decision을 JSONL에 append."""
        ...

    def read_findings(
        self,
        product: str | None = None,
        control_id: str | None = None,
        since: str | None = None
    ) -> list[dict]:
        """JSONL에서 findings를 필터링하여 읽는다."""
        ...
```

### 6-2. Evidence Report Generator

`orchestrator/evidence/export.py`:

```python
class EvidenceExporter:
    """
    Evidence report 생성기.
    JSONL + Controls Repository에서 audit-ready report를 생성한다.

    핵심 규칙:
    - Evidence는 generated artifact — DB가 아니다 (ADR-008).
    - Control ID가 전체를 관통하는 primary key.
    - MVP-0: JSON format만 지원.
    """

    def __init__(self, jsonl_reader: JsonlWriter, controls_repo: ControlsRepository): ...

    def export(
        self,
        product: str,
        control_id: str | None = None,
        period: str | None = None,     # "2026-Q3" format
        output_path: str = "output/evidence"
    ) -> dict:
        """
        Evidence report를 생성한다.

        Report 구조:
        {
          "report_id": "EVD-2026-0419-001",
          "generated_at": "2026-04-19T14:30:00Z",
          "product": "payment-api",
          "period": "2026-Q3",
          "controls": [
            {
              "control_id": "PCI-DSS-6.3.1",
              "title": "Security vulnerabilities are identified and addressed",
              "framework": "pci-dss-4.0",
              "status": "partial",      # full / partial / none
              "evidence": {
                "findings": [...],       # 해당 control의 findings
                "scanners_used": ["semgrep", "grype"],
                "last_scan": "2026-04-19T14:00:00Z",
                "risk_assessments": [...]  # 해당 control 관련 risk assessments
              }
            }
          ],
          "summary": {
            "total_controls": 12,
            "fully_evidenced": 8,
            "partially_evidenced": 3,
            "no_evidence": 1,
            "coverage_percentage": 91.7
          }
        }
        """
        ...

    def _determine_control_status(self, control: Control, findings: list[dict]) -> str:
        """
        컨트롤의 evidence 상태를 결정.
        - "full": 모든 verification_methods에 대해 최근 scan 결과 존재
        - "partial": 일부 verification_methods에 대해 scan 결과 존재
        - "none": scan 결과 없음
        """
        ...
```

### 6-3. 테스트

`tests/unit/test_jsonl_writer.py`:
- `test_write_finding_appends_to_file` — finding 1개 작성 → 파일에 1줄 추가
- `test_write_findings_appends_multiple` — 3개 findings → 3줄 추가
- `test_finding_entry_has_timestamp` — 각 엔트리에 timestamp 포함
- `test_finding_entry_has_hash` — 각 엔트리에 고유 hash 포함
- `test_read_findings_filter_by_product` — product 필터링
- `test_read_findings_filter_by_control_id` — control_id 필터링
- `test_write_gate_decision` — gate decision JSONL 기록

`tests/unit/test_evidence_export.py`:
- `test_export_produces_valid_report` — report에 필수 필드 포함
- `test_export_filter_by_control_id` — 특정 control만 포함
- `test_export_control_status_full` — 모든 scanner 결과 있음 → "full"
- `test_export_control_status_partial` — 일부 scanner 결과만 → "partial"
- `test_export_control_status_none` — 결과 없음 → "none"
- `test_export_coverage_percentage` — coverage 계산 정확성
- `test_export_writes_json_file` — output 디렉토리에 JSON 파일 생성

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. JSONL writer가 append-only인지 확인 (파일 덮어쓰기 X).
3. Evidence report에 Control ID가 primary key로 사용되는지 확인.
4. 네트워크 호출이 없는지 확인.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- SQLite나 다른 DB를 사용하지 마라. 이유: ADR-008. Evidence는 generated artifact.
- DefectDojo API를 호출하지 마라. 이유: MVP-0는 JSONL만 사용.
- output/ 디렉토리를 git에 커밋하지 마라. 이유: .gitignore에 포함.
- 파일을 덮어쓰지 마라 (truncate X). 이유: JSONL은 append-only.
