# Step 1: controls-repo

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md` — 특히 ADR-001 (RMF 방법론), ADR-005 (Grype gating)
- `/docs/PRD.md` — "Controls Repository" 섹션
- `/orchestrator/types.py` — Step 0에서 생성된 core types
- `/controls/products/payment-api/product-manifest.yaml` — Step 0에서 생성된 샘플

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 1-1. Control YAML Schema

각 컨트롤 YAML의 구조를 정의한다. `controls/baselines/` 디렉토리에 배치한다.

컨트롤 YAML 스키마 (OSCAL 호환 확장):

```yaml
control:
  id: "PCI-DSS-6.3.1"                  # 고유 ID (primary key)
  title: "Security vulnerabilities are identified and addressed"
  framework: "pci-dss-4.0"
  description: "..."
  verification_methods:
    - scanner: semgrep
      rules:
        - "python.lang.security.injection.*"
        - "python.django.security.*"
    - scanner: grype
      severity_threshold: high
    - scanner: checkov
      check_ids:
        - "CKV_AWS_18"
        - "CKV_AWS_19"
  applicable_tiers:
    - high
    - critical
  risk_tier_mapping:
    low: not-required
    medium: recommended
    high: required
    critical: required
```

### 1-2. Baseline 파일 생성 (3-5 controls per framework)

**`controls/baselines/pci-dss-4.0.yaml`** — 5개 컨트롤:
- PCI-DSS-1.3.4: Network segmentation — checkov `check_ids: [CKV_AWS_24]` (security group ingress)
- PCI-DSS-3.4: Render PAN unreadable — checkov `check_ids: [CKV_AWS_18, CKV_AWS_19]` (S3 logging + encryption)
- PCI-DSS-3.5.1: Restrict access to cryptographic keys — gitleaks
- PCI-DSS-6.3.1: Security vulnerabilities identified — semgrep `rules: ["python.lang.security.*"]` + grype `severity_threshold: high`
- PCI-DSS-10.2.1: Audit log coverage — sigma (detection)

**`controls/baselines/asvs-5.0-L3.yaml`** — 4개 컨트롤:
- ASVS-V2.10.1: No hardcoded credentials (gitleaks, semgrep)
- ASVS-V3.5.1: JWT validation requirements (semgrep)
- ASVS-V5.3.4: SQL injection prevention (semgrep)
- ASVS-V14.2.1: Dependency vulnerability management (grype)

**`controls/baselines/fisc-safety.yaml`** — 3개 컨트롤:
- FISC-SAFETY-15: Monitoring and detection — sigma
- FISC-DATA-03: Data protection at rest — checkov `check_ids: [CKV_AWS_19, CKV_AWS_21]` (S3 encryption + versioning)
- FISC-ACCESS-07: Access control enforcement — semgrep, checkov `check_ids: [CKV_AWS_1]` (IAM policy)

총 12개 컨트롤. 각 컨트롤은 위 스키마를 따르며, `verification_methods`에 구체적인 scanner rule 매핑을 포함한다.

### 1-3. Tier Mappings

`controls/tier-mappings.yaml`:

```yaml
tier_mappings:
  low:
    frameworks: []
    description: "No compliance requirements"
  medium:
    frameworks:
      - asvs-5.0-L3
    description: "Application security baseline"
  high:
    frameworks:
      - pci-dss-4.0
      - asvs-5.0-L3
    description: "Payment/financial data handling"
  critical:
    frameworks:
      - pci-dss-4.0
      - asvs-5.0-L3
      - fisc-safety
    description: "Regulated financial services in Japan"
```

### 1-4. ControlsRepository 클래스

`orchestrator/controls/repository.py`:

```python
class ControlsRepository:
    """Controls Repository — YAML 파일에서 컨트롤을 로드하고 baseline을 선택한다."""

    def __init__(self, baselines_dir: str, tier_mappings_path: str): ...

    def load_all(self) -> None:
        """baselines_dir의 모든 YAML 파일을 로드한다."""
        ...

    def get_control(self, control_id: str) -> Control:
        """Control ID로 단일 컨트롤을 반환한다."""
        ...

    def get_baseline_for_tier(self, tier: RiskTier) -> list[Control]:
        """tier-mappings.yaml에 따라 해당 tier에 적용되는 모든 컨트롤을 반환한다."""
        ...

    def get_controls_for_product(self, manifest: ProductManifest) -> list[Control]:
        """ProductManifest의 data_classification + jurisdiction으로 적용 가능한 컨트롤을 반환한다."""
        ...

    def get_verification_methods(self, control_id: str, scanner: str) -> list[dict]:
        """특정 컨트롤의 특정 scanner에 대한 verification method를 반환한다."""
        ...
```

`orchestrator/controls/models.py`:

```python
@dataclass
class Control:
    id: str
    title: str
    framework: str
    description: str
    verification_methods: list[VerificationMethod]
    applicable_tiers: list[RiskTier]
    risk_tier_mapping: dict[str, str]

@dataclass
class VerificationMethod:
    scanner: str                     # "semgrep", "checkov", "grype", "gitleaks", "sigma"
    rules: list[str] | None         # scanner-specific rule IDs
    check_ids: list[str] | None     # checkov check IDs
    severity_threshold: str | None  # "critical", "high", etc.
```

### 1-5. Baseline Selection 로직

`orchestrator/controls/baseline.py`:

```python
def select_baseline(
    repo: ControlsRepository,
    manifest: ProductManifest,
    tier: RiskTier
) -> list[Control]:
    """
    tier-mappings.yaml + product manifest를 기반으로 적용 컨트롤 목록을 반환.
    이 함수는 deterministic — AI가 관여하지 않는다.
    """
    ...
```

핵심 규칙:
- tier → frameworks 매핑은 `tier-mappings.yaml`에서 결정
- `applicable_tiers`에 현재 tier가 포함된 컨트롤만 선택
- `risk_tier_mapping`에서 현재 tier에 대해 "not-required"인 컨트롤은 제외
- 이 로직은 순수 lookup — AI가 개입하지 않는다 (ADR-004)

### 1-6. 테스트

`tests/unit/test_controls_repository.py`:
- `load_all()` — baselines 디렉토리에서 12개 컨트롤이 로드되는지 테스트
- `get_control("PCI-DSS-6.3.1")` — 올바른 컨트롤 반환 테스트
- `get_control("NONEXISTENT")` — KeyError 발생 테스트
- `get_baseline_for_tier(RiskTier.HIGH)` — PCI DSS + ASVS 컨트롤이 선택되는지 테스트
- `get_baseline_for_tier(RiskTier.LOW)` — 빈 리스트 반환 테스트
- `get_baseline_for_tier(RiskTier.CRITICAL)` — PCI DSS + ASVS + FISC 모두 선택되는지 테스트
- `get_verification_methods("PCI-DSS-6.3.1", "semgrep")` — semgrep 규칙 반환 테스트

`tests/unit/test_baseline_selection.py`:
- payment-api manifest + HIGH tier → 올바른 baseline 선택 테스트
- manifest에 PCI classification이 없으면 PCI 컨트롤 미적용 테스트

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `controls/baselines/` 디렉토리에 3개의 YAML 파일이 존재하는지 확인한다.
3. 각 YAML 파일이 위에 정의된 스키마를 따르는지 확인한다.
4. CRITICAL 규칙 확인: AI가 baseline 선택에 관여하지 않는지 확인한다.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- 컨트롤 내용을 임의로 만들지 마라. PCI DSS, ASVS, FISC의 실제 컨트롤 ID와 title을 사용하라. 이유: 컨트롤 ID가 거짓이면 플랫폼 전체의 신뢰성이 무너진다.
- 12개를 초과하는 컨트롤을 생성하지 마라. 이유: MVP-0는 최소한의 컨트롤로 아키텍처를 증명한다.
- Scanner를 실행하거나 import하지 마라. 이유: Scanner 통합은 Step 2에서 다룬다.
- `orchestrator/types.py`의 기존 타입을 변경하지 마라. 새로운 타입(`Control`, `VerificationMethod`)은 `orchestrator/controls/models.py`에 정의한다.
