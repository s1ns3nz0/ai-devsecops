# Step 4: risk-scoring

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "패턴: Strategy Pattern — AI 통합" 섹션
- `/docs/ADR.md` — ADR-001 (RMF 방법론)
- `/docs/PRD.md` — "리스크 평가 방법론" 섹션
- `/orchestrator/types.py` — RiskReport, RiskTier, Finding
- `/orchestrator/controls/repository.py` — ControlsRepository
- `/orchestrator/controls/baseline.py` — select_baseline
- `/orchestrator/scanners/` — Scanner wrappers, Finding 생성

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 4-1. RiskAssessor Protocol

`orchestrator/assessor/interface.py`:

```python
class RiskAssessor(Protocol):
    """
    Strategy pattern 인터페이스.
    StaticRiskAssessor와 BedrockRiskAssessor가 동일한 인터페이스를 구현한다.
    """

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """제품을 카테고리화하여 risk tier를 반환 (RMF Step 2)."""
        ...

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str
    ) -> RiskReport:
        """findings를 평가하여 risk report를 생성 (RMF Step 5)."""
        ...
```

### 4-2. Risk Scoring Engine

`orchestrator/scoring/risk.py`:

```python
def compute_risk_score(
    findings: list[Finding],
    manifest: ProductManifest,
    controls: list[Control]
) -> tuple[float, dict]:
    """
    Likelihood × Impact 기반 risk score 계산.
    SP 800-30 aligned: 모든 factor에 evidence를 기록.

    Returns:
        (risk_score: float 0-10, factors: dict with evidence per factor)

    Likelihood factors:
    - finding_severity_distribution: critical/high/medium/low 비율
    - pci_scope_ratio: PCI scope finding 비율
    - secrets_detected: boolean (있으면 likelihood 상승)

    Impact factors:
    - data_classification: PCI > PII-financial > PII-general > public
    - control_coverage: 필요 컨트롤 대비 커버된 비율
    - jurisdiction_sensitivity: JP(FISC) > EU(GDPR) > other

    Score = (likelihood_score * 0.5 + impact_score * 0.5)
    각 score는 0-10 범위.
    """
    ...
```

### 4-3. StaticRiskAssessor

`orchestrator/assessor/static.py`:

```python
class StaticRiskAssessor:
    """
    AI 없이 동작하는 risk assessor.
    Deterministic 로직만 사용한다.

    categorize: data_classification 기반 룩업
    assess: compute_risk_score + 템플릿 기반 narrative
    """

    def __init__(self, controls_repo: ControlsRepository): ...

    def categorize(self, manifest: ProductManifest) -> RiskTier:
        """
        Categorization 규칙 (deterministic):
        - PCI in data_classification → HIGH 이상
        - PCI + JP jurisdiction → CRITICAL
        - PII-financial → MEDIUM 이상
        - 그 외 → LOW
        """
        ...

    def assess(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
        controls: list[Control],
        trigger: str
    ) -> RiskReport:
        """
        Static assessment:
        1. compute_risk_score로 점수 계산
        2. 템플릿 기반 narrative 생성 (AI 없음)
        3. RiskReport 반환
        """
        ...
```

narrative 템플릿 예시:
```
"Risk Assessment for {product}: {trigger} trigger.
Found {n_critical} critical, {n_high} high findings across {n_controls} controls.
Data classification: {classifications}. Risk score: {score}/10.
Gate recommendation: {recommendation}."
```

### 4-4. Risk Report ID 생성

`RA-{YYYY}-{MMDD}-{NNN}` 형식. 날짜 기반 + 순번.

### 4-5. 테스트

`tests/unit/test_risk_scoring.py`:
- `test_no_findings_low_score` — finding 0개 → score < 3.0
- `test_critical_findings_high_score` — critical finding 3개 → score > 7.0
- `test_pci_scope_increases_impact` — PCI data classification → impact 상승
- `test_secrets_increase_likelihood` — secret finding → likelihood 상승
- `test_score_range` — score가 항상 0.0-10.0 범위
- `test_factors_contain_evidence` — 반환된 factors dict에 각 factor의 evidence 포함

`tests/unit/test_static_assessor.py`:
- `test_categorize_pci` — PCI data → HIGH tier
- `test_categorize_pci_jp` — PCI + JP → CRITICAL tier
- `test_categorize_pii` — PII-financial → MEDIUM tier
- `test_categorize_public` — data_classification 없음 → LOW tier
- `test_assess_produces_risk_report` — findings → RiskReport 반환
- `test_assess_narrative_is_not_empty` — narrative가 빈 문자열이 아닌지 확인
- `test_assess_report_id_format` — ID가 RA-YYYY-MMDD-NNN 형식인지 확인

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `RiskAssessor` protocol과 `StaticRiskAssessor` implementation이 동일한 인터페이스를 따르는지 확인한다.
3. `compute_risk_score`가 factor별 evidence를 반환하는지 확인한다 (감사 추적).
4. CRITICAL 규칙 확인: StaticRiskAssessor에 네트워크 호출이나 AI 호출이 없는지 확인한다.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- BedrockRiskAssessor를 이 step에서 구현하지 마라. 이유: Step 5에서 다룬다.
- boto3를 import하지 마라. 이유: AI 연동은 Step 5.
- Gate 결정을 StaticRiskAssessor에서 하지 마라. 이유: Gate는 ThresholdEvaluator (Step 3)의 책임. Assessor는 risk_score와 narrative만 제공한다.
- risk_score를 랜덤이나 임의 값으로 생성하지 마라. 이유: 감사 추적이 가능한 deterministic 계산이어야 한다.
