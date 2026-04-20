# Step 9: demo-integration

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md` — 명령어 섹션 (make demo)
- `/docs/ARCHITECTURE.md` — 전체 시스템 아키텍처, "MVP-0 → MVP 확장 경로"
- `/docs/PRD.md` — "E2E 시나리오", "Sample App" 섹션
- `/orchestrator/cli.py` — CLI commands (Step 8)
- `/Makefile` — 기존 make targets

이전 step에서 만들어진 모든 코드를 꼼꼼히 읽고, 전체 흐름을 파악한 뒤 작업하라.

## 작업

### 9-1. Sample App Fixture

`tests/fixtures/sample-app/` 디렉토리에 scanner가 스캔할 수 있는 fixture 파일을 생성한다.

**`tests/fixtures/sample-app/src/app.py`** — 의도적 취약점 포함:
- Hardcoded AWS access key (gitleaks 탐지)
- SQL injection 취약점 (semgrep 탐지)
- PII를 로그에 출력 (semgrep 탐지)
- 약한 JWT secret (semgrep 탐지)

**`tests/fixtures/sample-app/src/config.py`** — hardcoded credentials:
- AWS_SECRET_ACCESS_KEY = "AKIA..." (gitleaks 탐지)

**`tests/fixtures/sample-app/terraform/main.tf`** — IaC 취약점:
- S3 bucket without encryption (checkov 탐지: CKV_AWS_19)
- S3 bucket without versioning (checkov 탐지: CKV_AWS_21)
- Overly permissive IAM policy (checkov 탐지: CKV_AWS_1)
- Security group with 0.0.0.0/0 ingress (checkov 탐지: CKV_AWS_24)

**`tests/fixtures/sample-app/requirements.txt`** — 알려진 CVE 포함:
- `cryptography==3.4.6` (CVE 있는 이전 버전)
- `requests==2.25.0` (알려진 취약점)
- `pyjwt==1.7.0` (알려진 취약점)

**`tests/fixtures/sample-app/logs/access.jsonl`** — Step 7의 fixture와 동일하거나 확장:
- 정상 요청 + 공격 패턴 로그

### 9-2. Demo Script

`orchestrator/demo.py` (CLI의 assess, detect, export 함수를 재사용 — 로직을 중복하지 않는다).

**중요:** `orchestrator/cli.py`에 `demo` 명령을 등록해야 한다:

```python
@cli.command()
@click.argument("target_path")
@click.option("--product", default="payment-api")
def demo(target_path: str, product: str):
    """Run the full MVP-0 demo."""
    from orchestrator.demo import run_demo
    run_demo(target_path, product)
```

`run_demo` 함수:

```python
def run_demo(target_path: str, product: str = "payment-api") -> None:
    """
    MVP-0 E2E 데모를 실행한다.

    Flow:
    1. Product manifest + risk profile 로드
    2. Controls Repository 로드 + baseline 선택
    3. Risk tier 결정 (categorize)
    4. 모든 scanner 실행
    5. Gate 평가
    6. Risk assessment
    7. Sigma detection (로그 분석)
    8. Evidence export
    9. 결과 summary 출력

    출력 형식:
    [1/7] Loading product manifest: payment-api
          Product: payment-api | Data: PCI, PII-financial | Tier: high

    [2/7] Selecting control baseline (RMF Step 3: Select)
          Frameworks applied: PCI-DSS-4.0 (5), ASVS-5.0-L3 (4), FISC (3)
          Total controls: 12

    [3/7] Running scanners (RMF Step 5: Assess)
          Checkov: N findings
          Semgrep: N findings
          Grype: N findings
          Gitleaks: N findings

    [4/7] Gate evaluation (RMF Step 6: Authorize)
          BLOCKED / PASSED — reason

    [5/7] Risk assessment
          Risk score: X.X/10
          Mode: static / AI-augmented

    [6/7] Detection analysis
          Sigma rules: N matches
          ATT&CK coverage: T1110, T1190, T1048, T1078

    [7/7] Evidence export
          Report: output/evidence/payment-api-evidence.json
          Controls coverage: XX.X%

    ✓ Demo complete. See output/ for full results.
    """
    ...
```

### 9-3. Makefile 업데이트

기존 Makefile에 demo 관련 target 추가:

```makefile
demo:
	@python -m orchestrator demo tests/fixtures/sample-app --product payment-api

demo-full:
	@BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0 python -m orchestrator demo tests/fixtures/sample-app --product payment-api
```

MVP-0에서는 Docker 없이 로컬 fixture로 데모를 실행한다. `demo-docker` 이름은 MVP tier에서 실제 Docker Compose를 사용할 때 추가한다.

### 9-4. README 업데이트

프로젝트 루트에 `README.md`를 생성한다 (또는 업데이트):

```markdown
# Compliance-Driven AI Risk Platform

Plug in your compliance frameworks. The platform determines what to scan,
when, and why — then produces audit-ready evidence.

## Quick Start

\```bash
git clone <repo>
cd compliance-ai-risk-platform
make setup
make demo
\```

## How It Works

1. Define your product (data classification, jurisdiction, deployment)
2. Platform selects applicable compliance controls
3. Scanners run automatically, findings tagged with Control IDs
4. Gate evaluates findings against your risk thresholds
5. Evidence exported with full traceability

Works without AI. Transforms with AI.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
```

간결하게. 5줄 이내의 quick start.

### 9-5. 테스트

`tests/unit/test_demo.py`:
- `test_demo_runs_without_error` — fixture 기반 demo가 에러 없이 실행
- `test_demo_produces_evidence_file` — output/ 디렉토리에 evidence JSON 생성
- `test_demo_produces_jsonl` — output/findings.jsonl 생성
- `test_demo_produces_risk_assessment` — risk-assessments/ 디렉토리에 YAML 생성

scanner는 mock하여 fixture 출력을 반환하도록 한다. 실제 CLI 실행은 integration test.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

참고: `make demo`는 scanner CLI가 설치되어 있어야 실행 가능하다. AC에는 포함하지 않되, 검증 절차에서 선택적으로 확인한다.

## 검증 절차

1. `make test && make lint`를 실행한다.
2. `make demo`를 실행한다 (scanner 미설치 시 graceful 에러 허용).
3. fixture 파일들이 실제 scanner output format을 따르는지 확인한다.
4. output/ 디렉토리에 evidence report가 생성되는지 확인한다.
5. README.md가 존재하고 Quick Start가 정확한지 확인한다.
6. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- Docker Compose를 이 step에서 구성하지 마라. 이유: MVP-0는 Docker 없이 fixture 기반. DefectDojo + DT는 MVP tier.
- 실제 GitHub repo를 auto-clone하지 마라. 이유: MVP-0는 로컬 fixture 사용. auto-clone은 MVP tier.
- sample-app fixture에 실제 AWS 키나 비밀번호를 넣지 마라. 이유: 보안. 가짜 키를 사용하되 scanner가 탐지할 수 있는 형식이어야 한다 (e.g., AKIA로 시작하는 가짜 키).
- `scripts/` 디렉토리의 harness 관련 파일을 수정하지 마라.
