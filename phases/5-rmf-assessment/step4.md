# Step 4: poam-authorization

## 읽어야 할 파일

- `/orchestrator/rmf/models.py` — RiskResponse, SP80030Report
- `/orchestrator/rmf/sar.py` — SecurityAssessmentReport (Step 3)
- `/orchestrator/types.py` — Finding, GateDecision
- `/orchestrator/resilience/override.py` — OverrideRecord (기존 override)

## 작업

### 4-1. Plan of Action & Milestones (POA&M)

`orchestrator/rmf/poam.py`:

```python
@dataclass
class POAMItem:
    """Single weakness + remediation plan."""
    id: str                      # POAM-YYYY-MMDD-NNN
    weakness: str                # what's wrong
    control_id: str              # which control is affected
    source: str                  # "semgrep" / "grype" / "checkov" / etc.
    finding_id: str              # CVE or rule ID
    severity: str                # very-high / high / moderate / low / very-low
    risk_level: str              # from SP 800-30 assessment
    status: str                  # "open" / "in-progress" / "completed" / "accepted"

    # Milestones
    milestones: list[dict[str, str]]  # [{description, target_date, status}]
    scheduled_completion: str    # target date
    responsible: str             # "security-engineer" / "dev-team" / etc.
    cost_estimate: str           # "low" / "moderate" / "high"

    # Links
    finding_evidence: str        # reference to JSONL/DefectDojo
    override_id: str             # if overridden, link to OverrideRecord

@dataclass
class AuthorizationDecision:
    """RMF Step 6 authorization decision."""
    decision: str                # "ATO" / "DATO" / "ATO-with-conditions"
    risk_level: str              # overall risk from SP 800-30
    conditions: list[str]        # POA&M items required for ATO-with-conditions
    authorizer: str              # "automated-gate" or role
    timestamp: str
    valid_until: str             # re-authorization date
    reasoning: str

class POAMGenerator:
    """Generate POA&M from findings + risk assessment.

    Maps:
    - critical/high findings → POA&M items with deadlines
    - SP 800-30 risk responses → milestones
    - Override records → linked POA&M items
    """

    def generate(
        self,
        findings: list[Finding],
        risk_report: SP80030Report | None = None,
        gate_decision: GateDecision | None = None,
    ) -> list[POAMItem]:
        """
        Generate POA&M items.

        Priority → deadline mapping:
        - very-high risk: 7 days
        - high risk: 30 days
        - moderate risk: 90 days
        - low risk: 180 days

        Each item has milestones:
        1. Identify fix (day 1)
        2. Implement fix (50% of deadline)
        3. Verify in staging (75% of deadline)
        4. Deploy to production (deadline)
        """
        ...

class AuthorizationEngine:
    """RMF Step 6 authorization decision.

    Maps:
    - Gate PASS + no very-high risks → ATO
    - Gate BLOCK → DATO
    - Gate PASS + override active → ATO-with-conditions
    - Gate PASS + open POA&M items → ATO-with-conditions
    """

    def decide(
        self,
        gate_decision: GateDecision,
        poam_items: list[POAMItem],
        overrides: list[dict[str, object]] | None = None,
    ) -> AuthorizationDecision:
        ...
```

### 4-2. 테스트

`tests/unit/test_poam.py`:
- `test_critical_finding_creates_poam_item` — critical → 7-day deadline
- `test_high_finding_creates_poam_item` — high → 30-day deadline
- `test_poam_has_milestones` — 4 milestones per item
- `test_poam_links_to_control` — control_id 매핑
- `test_gate_pass_no_risk_ato` — gate pass + clean → ATO
- `test_gate_block_dato` — gate block → DATO
- `test_gate_pass_with_poam_ato_conditions` — gate pass + open items → ATO-with-conditions
- `test_override_creates_conditional_poam` — override → linked POA&M

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- AI를 POA&M/authorization에 사용하지 마라. Deterministic 로직.
- 기존 override 메커니즘을 수정하지 마라. POA&M은 override와 연동하되 독립.
