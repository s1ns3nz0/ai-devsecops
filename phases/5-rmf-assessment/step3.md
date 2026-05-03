# Step 3: sar-report

## 읽어야 할 파일

- `/orchestrator/rmf/models.py` — SP80030Report (Step 1)
- `/orchestrator/evidence/export.py` — 기존 EvidenceExporter
- `/orchestrator/controls/repository.py` — ControlsRepository
- `/orchestrator/types.py` — Finding, GateDecision

## 작업

### 3-1. Security Assessment Report (SAR)

`orchestrator/rmf/sar.py`를 생성한다:

```python
@dataclass
class ControlAssessment:
    """Per-control assessment status (RMF Step 5)."""
    control_id: str
    title: str
    framework: str
    status: str                  # "satisfied" / "other-than-satisfied" / "not-assessed"
    evidence_type: str           # "automated" / "manual" / "none"
    assessor: str                # "semgrep" / "checkov" / "manual review required"
    findings_count: int
    findings_summary: str        # brief description of what was found
    risk_level: str              # from SP 800-30 assessment

@dataclass
class SecurityAssessmentReport:
    """SAR — RMF Step 5 deliverable."""
    report_id: str               # SAR-YYYY-MMDD-NNN
    product: str
    generated_at: str
    system_description: str      # from manifest
    assessment_methodology: str  # "Automated scanning + SP 800-30 risk assessment"

    # Per-control results
    control_assessments: list[ControlAssessment]

    # Summary statistics
    total_controls: int
    satisfied: int
    other_than_satisfied: int
    not_assessed: int
    coverage_percentage: float

    # Linked risk assessment
    risk_assessment_id: str      # SP80030Report reference

    # Overall determination
    overall_risk: str            # "acceptable" / "unacceptable"
    authorization_recommendation: str  # "ATO" / "DATO" / "ATO-with-conditions"

class SARGenerator:
    """Generate Security Assessment Report from findings + controls.

    Maps:
    - Controls with scanner findings → "satisfied" (automated evidence)
    - Controls with findings flagging issues → "other-than-satisfied"
    - Controls with no scanner mapping → "not-assessed" (manual review needed)
    """

    def __init__(self, controls_repo: ControlsRepository): ...

    def generate(
        self,
        product: str,
        findings: list[Finding],
        gate_decision: GateDecision,
        risk_report: SP80030Report | None = None,
    ) -> SecurityAssessmentReport:
        """Generate SAR."""
        ...

    def _assess_control(
        self,
        control: Control,
        findings: list[Finding],
    ) -> ControlAssessment:
        """Assess a single control.

        Logic:
        - Has verification_methods AND scanner ran AND 0 issues → "satisfied"
        - Has verification_methods AND scanner ran AND issues found → "other-than-satisfied"
        - Has verification_methods but scanner NOT in findings → "not-assessed"
        - No verification_methods → "not-assessed" (manual only)
        """
        ...
```

### 3-2. 테스트

`tests/unit/test_sar.py`:
- `test_sar_has_all_controls` — 102 controls assessed
- `test_satisfied_when_scanner_ran_no_issues` — clean scan → satisfied
- `test_other_than_satisfied_when_issues_found` — findings → other-than-satisfied
- `test_not_assessed_when_no_scanner_ran` — no evidence → not-assessed
- `test_coverage_percentage` — satisfied / total
- `test_authorization_recommendation` — gate PASS → ATO, gate BLOCK → DATO

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- AI를 SAR 생성에 사용하지 마라. SAR은 deterministic (findings 기반).
- 기존 EvidenceExporter를 수정하지 마라. SAR은 별도 보고서.
