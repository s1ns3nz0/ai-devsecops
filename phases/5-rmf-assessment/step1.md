# Step 1: sp800-30-models

## 읽어야 할 파일

- `/CLAUDE.md`
- `/orchestrator/types.py` — 기존 RiskReport
- `/orchestrator/intelligence/models.py` — EnrichedVulnerability
- `/orchestrator/intelligence/threat_model.py` — ThreatScenario, ThreatActor

## 작업

### 1-1. SP 800-30 Risk Assessment Data Models

`orchestrator/rmf/models.py`를 생성한다. SP 800-30 Rev 1의 4-phase 구조를 반영:

```python
@dataclass
class ThreatSource:
    """SP 800-30 Table D-1: Threat source identification."""
    id: str
    type: str                    # adversarial | accidental | structural | environmental
    name: str                    # "External attacker" / "Insider" / "System failure"
    capability: str              # very-low / low / moderate / high / very-high
    intent: str                  # SP 800-30 Table D-2 (adversarial only)
    targeting: str               # SP 800-30 Table D-3 (adversarial only)

@dataclass
class ThreatEvent:
    """SP 800-30 Table E: Threat event identification."""
    id: str
    description: str
    source_id: str               # ThreatSource reference
    mitre_technique: str         # ATT&CK mapping
    relevance: str               # confirmed / expected / predicted / possible
    cve_id: str                  # CVE if applicable
    target_component: str        # SBOM component or code path

@dataclass
class LikelihoodAssessment:
    """SP 800-30 Table G-3 through G-6."""
    initiation_likelihood: str   # very-low / low / moderate / high / very-high
    impact_likelihood: str       # given initiation, likelihood of adverse impact
    overall_likelihood: str      # combined
    epss_score: float | None     # EPSS exploit probability (supplementary)
    predisposing_conditions: list[str]  # "internet-facing", "PCI scope", etc.
    evidence: str                # reasoning for the determination

@dataclass
class ImpactAssessment:
    """SP 800-30 Table G-7 through G-9."""
    impact_type: str             # harm to operations / assets / individuals / nation
    cia_impact: dict[str, str]   # {confidentiality: high, integrity: high, availability: moderate}
    severity: str                # very-low / low / moderate / high / very-high
    compliance_impact: list[str] # controls violated
    business_impact: str         # business consequence description
    evidence: str

@dataclass
class RiskDetermination:
    """SP 800-30 Table G-10: Risk = Likelihood × Impact."""
    threat_event_id: str
    likelihood: str              # from LikelihoodAssessment
    impact: str                  # from ImpactAssessment
    risk_level: str              # very-low / low / moderate / high / very-high
    risk_score: float            # 0-100 semi-quantitative

@dataclass
class RiskResponse:
    """SP 800-30 risk response."""
    risk_determination_id: str
    response_type: str           # accept / avoid / mitigate / share / transfer
    description: str
    milestones: list[str]        # remediation steps
    deadline: str                # target completion date
    responsible: str             # role responsible

@dataclass
class SP80030Report:
    """Complete SP 800-30 risk assessment report."""
    report_id: str               # RA-SP800-30-YYYY-MMDD-NNN
    product: str
    generated_at: str
    mode: str                    # "ai" | "static"
    methodology: str             # "NIST SP 800-30 Rev 1"

    # Phase 1: Prepare
    scope: str
    risk_model: str              # "semi-quantitative, threat-oriented"
    assumptions: list[str]
    cia_impact_levels: dict[str, str]

    # Phase 2: Conduct
    threat_sources: list[ThreatSource]
    threat_events: list[ThreatEvent]
    likelihood_assessments: list[LikelihoodAssessment]
    impact_assessments: list[ImpactAssessment]
    risk_determinations: list[RiskDetermination]

    # Phase 3: Communicate
    executive_summary: str
    risk_responses: list[RiskResponse]
    recommendations: list[str]

    # Phase 4: Maintain
    reassessment_triggers: list[str]
    next_review_date: str
```

### 1-2. 테스트

`tests/unit/test_sp800_30_models.py`:
- `test_threat_source_creation` — ThreatSource 생성
- `test_threat_event_with_cve` — CVE 매핑된 ThreatEvent
- `test_likelihood_with_epss` — EPSS 포함 LikelihoodAssessment
- `test_risk_determination_matrix` — likelihood × impact → risk level
- `test_sp800_30_report_has_all_phases` — 전체 보고서 구조 검증
- `test_risk_response_types` — 5가지 response type 검증

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- AI를 이 step에서 호출하지 마라. 데이터 모델만 정의.
- 기존 RiskReport를 수정하지 마라. SP80030Report는 별도 모델.
