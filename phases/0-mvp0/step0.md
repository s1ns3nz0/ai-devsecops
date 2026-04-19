# Step 0: project-and-types

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `/docs/PRD.md`
- `/AGENTS.md`

## 작업

### 0-1. 프로젝트 스켈레톤

`pyproject.toml`을 생성한다:

- 프로젝트명: `compliance-ai-risk-platform`
- Python >=3.11
- 의존성: `pyyaml`, `jsonschema`, `click` (CLI), `boto3` (Bedrock — optional)
- dev 의존성: `pytest`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML`, `types-jsonschema`
- ruff 설정: line-length=120, target Python 3.11
- mypy 설정: strict mode. `[[tool.mypy.overrides]]`로 `boto3` 모듈에 `ignore_missing_imports = true` 설정 (boto3-stubs는 Step 5에서 추가)
- pytest 설정: `testpaths = ["tests"]`

`Makefile`을 생성한다:

```makefile
setup:       pip install -e ".[dev]"
test:        pytest tests/unit/ -v
test-contract: pytest tests/contract/ -v
lint:        ruff check . && mypy orchestrator/
```

`.env.example`을 생성한다:

```
# AWS Bedrock (optional — platform works without it)
AWS_REGION=ap-northeast-1
AWS_PROFILE=default
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0

# Platform
LOG_LEVEL=INFO
SAMPLE_APP_REPO=https://github.com/example/sample-vulnerable-app
```

ARCHITECTURE.md에 정의된 디렉토리 구조를 생성한다. 각 Python 패키지 디렉토리에 `__init__.py`를 배치한다:

```
orchestrator/
├── __init__.py
├── __main__.py          # placeholder: print("orchestrator CLI")
├── assessor/
│   └── __init__.py
├── scanners/
│   └── __init__.py
├── gate/
│   └── __init__.py
├── controls/
│   └── __init__.py
├── evidence/
│   └── __init__.py
├── sigma/
│   └── __init__.py
├── config/
│   ├── __init__.py
│   └── schemas/          # JSON Schema files
└── scoring/
    └── __init__.py
tests/
├── __init__.py
├── unit/
│   └── __init__.py
├── contract/
│   └── __init__.py
├── fixtures/
│   └── sample-app/      # scanner fixture 파일용 (이후 step에서 채움)
└── conftest.py          # shared fixtures (아래 0-5 참조)
controls/
├── baselines/
├── products/
│   └── payment-api/
│       └── risk-assessments/
└── tier-mappings.yaml   # placeholder
sigma/
└── rules/
rego/
└── gates/
output/                  # .gitignore에 추가
```

`.gitignore`에 `output/`, `*.jsonl`, `__pycache__/`, `.mypy_cache/`, `*.egg-info/`, `dist/`, `.env`를 추가한다.

### 0-2. Core Types

`orchestrator/types.py`에 핵심 데이터 클래스를 정의한다. `dataclasses`와 `enum`을 사용한다:

```python
# 시그니처만 제시. 필요한 필드와 구현은 에이전트 재량.

class RiskTier(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ProductManifest:
    """product-manifest.yaml 파싱 결과"""
    name: str
    description: str
    data_classification: list[str]   # ["PCI", "PII-financial"]
    jurisdiction: list[str]          # ["JP"]
    deployment: dict                 # cloud, compute, region
    # ... 필요한 필드 추가

@dataclass
class RiskProfile:
    """risk-profile.yaml 파싱 결과"""
    frameworks: list[str]
    risk_appetite: str               # conservative/moderate/aggressive
    thresholds: dict                 # per-tier gate thresholds
    failure_policy: dict             # per-tier failure behavior
    # ... 필요한 필드 추가

@dataclass
class Finding:
    """스캐너 결과 단일 항목"""
    source: str                      # "semgrep", "checkov", "grype", "gitleaks"
    rule_id: str
    severity: str                    # "critical", "high", "medium", "low", "info"
    file: str
    line: int
    message: str
    control_ids: list[str]           # ["PCI-DSS-6.3.1", "ASVS-V5.3.4"]
    product: str
    # ... 필요한 필드 추가

@dataclass
class RiskReport:
    """리스크 평가 결과"""
    id: str                          # RA-YYYY-MMDD-NNN
    trigger: str                     # pre_merge, pre_deploy, periodic, etc.
    product: str
    risk_tier: RiskTier
    likelihood: str
    impact: str
    risk_score: float
    narrative: str                   # AI가 작성하거나 static template
    findings_summary: dict
    affected_controls: list[str]
    gate_recommendation: str         # proceed, hold_for_review, block
    # ... 필요한 필드 추가

@dataclass
class GateDecision:
    """Gate 평가 결과"""
    passed: bool
    reason: str                      # 차단 사유 또는 "all checks passed"
    threshold_results: dict          # 각 threshold별 pass/fail
    findings_count: dict             # severity별 카운트
```

### 0-3. Config Parsers

`orchestrator/config/manifest.py`:
- `load_manifest(path: str) -> ProductManifest` — YAML 로드 + validation
- JSON Schema로 필수 필드 검증

`orchestrator/config/profile.py`:
- `load_profile(path: str) -> RiskProfile` — YAML 로드 + validation
- JSON Schema로 필수 필드 검증

`orchestrator/config/schemas/` 디렉토리에 `manifest_schema.json`, `profile_schema.json`을 생성한다.

### 0-4. Fixture 설정

`controls/products/payment-api/product-manifest.yaml` 샘플:

```yaml
product:
  name: payment-api
  description: "QR code payment confirmation service"
  data_classification:
    - PCI
    - PII-financial
  jurisdiction:
    - JP
  deployment:
    cloud: AWS
    compute: EKS
    region: ap-northeast-1
  integrations:
    - external-payment-gateway
    - internal-user-db
```

`controls/products/payment-api/risk-profile.yaml` 샘플:

```yaml
risk_profile:
  frameworks:
    - pci-dss-4.0
    - asvs-5.0-L3
    - fisc-safety
  risk_appetite: conservative
  thresholds:
    critical:
      max_critical_findings: 0
      max_secrets_detected: 0
      action: block
    high:
      max_critical_findings: 0
      max_high_findings_pci: 0
      action: block
    medium:
      max_high_findings: 5
      action: proceed
    low:
      action: proceed
  failure_policy:
    critical:
      scan_failure: block
    high:
      scan_failure: block
    medium:
      scan_failure: proceed
    low:
      scan_failure: proceed
```

### 0-5. Shared Test Fixtures

`tests/conftest.py`에 공통 fixture를 정의한다:

```python
@pytest.fixture
def sample_manifest() -> ProductManifest:
    """payment-api product manifest fixture."""
    ...

@pytest.fixture
def sample_profile() -> RiskProfile:
    """conservative risk profile fixture."""
    ...

@pytest.fixture
def sample_finding() -> Finding:
    """PCI-DSS-6.3.1 mapped semgrep finding fixture."""
    ...

@pytest.fixture
def sample_findings() -> list[Finding]:
    """Mixed severity findings for gate/scoring tests."""
    ...
```

### 0-6. 테스트

`tests/unit/test_types.py`:
- 각 dataclass의 생성 및 필드 접근 테스트
- RiskTier enum 값 테스트
- Finding에 control_ids가 빈 리스트일 때 동작 테스트

`tests/unit/test_config.py`:
- `load_manifest`가 올바른 YAML을 파싱하는지 테스트
- 필수 필드 누락 시 ValidationError 발생 테스트
- `load_profile`이 올바른 YAML을 파싱하는지 테스트
- 필수 필드 누락 시 ValidationError 발생 테스트

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && pip install -e ".[dev]" && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - ARCHITECTURE.md 디렉토리 구조를 따르는가?
   - ADR 기술 스택(Python 3.11+, YAML, JSON Schema)을 벗어나지 않았는가?
   - CLAUDE.md CRITICAL 규칙을 위반하지 않았는가?
3. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- 실제 스캐너(Checkov, Semgrep 등)를 설치하거나 실행하지 마라. 이유: 이 step은 타입과 구조만 정의한다.
- `boto3`를 import하거나 AWS API를 호출하지 마라. 이유: Bedrock 연동은 Step 5에서 다룬다.
- `click` CLI 명령을 구현하지 마라. 이유: CLI는 Step 8에서 다룬다. `__main__.py`는 placeholder만.
- 기존 `scripts/` 디렉토리의 파일을 수정하지 마라. 이유: harness executor는 별도 시스템이다.
- `controls/baselines/`에 컨트롤 YAML 파일을 생성하지 마라. 이유: Controls Repository는 Step 1에서 다룬다.
