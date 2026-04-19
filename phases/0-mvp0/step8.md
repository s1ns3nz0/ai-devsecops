# Step 8: cli-commands

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md` — 명령어 섹션
- `/docs/ARCHITECTURE.md` — 전체 데이터 흐름, 디렉토리 구조
- `/docs/PRD.md` — "E2E 시나리오", "orchestrator init" 관련
- `/orchestrator/assessor/interface.py` — RiskAssessor protocol
- `/orchestrator/assessor/static.py` — StaticRiskAssessor
- `/orchestrator/assessor/bedrock.py` — BedrockRiskAssessor
- `/orchestrator/scanners/runner.py` — ScannerRunner
- `/orchestrator/gate/threshold.py` — ThresholdEvaluator
- `/orchestrator/evidence/jsonl.py` — JsonlWriter
- `/orchestrator/evidence/export.py` — EvidenceExporter
- `/orchestrator/controls/repository.py` — ControlsRepository
- `/orchestrator/controls/baseline.py` — select_baseline
- `/orchestrator/config/manifest.py` — load_manifest
- `/orchestrator/config/profile.py` — load_profile
- `/orchestrator/sigma/engine.py` — SigmaEngine

이전 step에서 만들어진 모든 코드를 꼼꼼히 읽고, 각 컴포넌트의 인터페이스를 파악한 뒤 작업하라.

## 작업

### 8-1. CLI Entry Point

`orchestrator/__main__.py`를 수정하여 click CLI를 구현한다:

```python
# python -m orchestrator <command>
```

### 8-2. CLI Commands

`orchestrator/cli.py`:

```python
import click

@click.group()
def cli():
    """Compliance-Driven AI Risk Platform"""
    ...

@cli.command()
def init():
    """
    product-manifest.yaml과 risk-profile.yaml을 대화형으로 생성.

    Static mode (default):
    - 사용자에게 질문 (product name, data classification, jurisdiction, deployment 등)
    - 답변 기반으로 YAML 파일 생성
    - risk tier 자동 결정 (StaticRiskAssessor.categorize)

    AI mode (--ai flag + Bedrock configured):
    - "Describe your product:" 프롬프트
    - 사용자 입력을 BedrockRiskAssessor.categorize에 전달
    - AI가 생성한 manifest를 사용자에게 보여주고 승인 요청

    Output: controls/products/{name}/product-manifest.yaml
            controls/products/{name}/risk-profile.yaml
    """
    ...

@cli.command()
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
def scan(target_path: str, product: str):
    """
    target_path를 스캔하고 findings를 JSONL에 기록.

    Flow:
    1. load_manifest + load_profile
    2. ControlsRepository 로드 + select_baseline
    3. ScannerRunner.run_all(target_path)
    4. ControlMapper로 findings에 control_ids 태깅
    5. JsonlWriter로 findings 기록
    6. 결과 summary 출력
    """
    ...

@cli.command()
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--trigger", default="pre_merge", type=click.Choice(["pre_merge", "pre_deploy", "periodic"]))
def assess(target_path: str, product: str, trigger: str):
    """
    전체 risk assessment 수행 (scan + gate + risk report).

    Flow:
    1. scan command와 동일한 스캔 수행
    2. ThresholdEvaluator.evaluate로 gate 결정
    3. RiskAssessor.assess로 risk report 생성 (Static 또는 Bedrock)
    4. 결과를 JSONL에 기록
    5. risk report를 controls/products/{product}/risk-assessments/에 YAML 저장
    6. 결과 출력 (gate decision + risk score + narrative)

    Exit code:
    - 0: gate passed
    - 1: gate failed (blocked)
    """
    ...

@cli.command()
@click.option("--product", required=True)
@click.option("--control-id", default=None)
@click.option("--period", default=None)
@click.option("--output", default="output/evidence")
def export(product: str, control_id: str | None, period: str | None, output: str):
    """
    Evidence report를 JSON으로 생성.

    Flow:
    1. JsonlWriter에서 findings 읽기
    2. ControlsRepository에서 controls 로드
    3. EvidenceExporter.export 실행
    4. JSON 파일 저장
    """
    ...

@cli.command()
@click.argument("log_path")
@click.option("--product", default="")
def detect(log_path: str, product: str):
    """
    Sigma rules로 로그 파일을 분석.

    Flow:
    1. SigmaEngine.load_rules
    2. SigmaEngine.evaluate_log_file(log_path)
    3. SigmaMatch.to_finding()으로 Finding 변환
    4. JsonlWriter로 findings 기록 (evidence chain 연결)
    5. 매칭 결과 출력 (rule title, ATT&CK tag, Control ID)
    """
    ...
```

### 8-3. Assessor 선택 로직

`orchestrator/cli.py` 내부 또는 별도 모듈:

```python
def get_assessor(controls_repo: ControlsRepository) -> RiskAssessor:
    """
    환경에 따라 적절한 RiskAssessor를 반환.
    - BEDROCK_MODEL_ID 환경변수가 설정되고 boto3 import 가능 → BedrockRiskAssessor
    - 그 외 → StaticRiskAssessor
    """
    ...
```

### 8-4. Output Formatting

CLI 출력은 구조화된 형식으로:

```
$ python -m orchestrator assess ./sample-app --product payment-api

[1/4] Loading configuration
      Product: payment-api | Tier: high | Frameworks: PCI-DSS, ASVS, FISC

[2/4] Running scanners
      Checkov: 3 findings (1 critical, 1 high, 1 medium)
      Semgrep: 2 findings (1 high, 1 medium)
      Grype:   1 finding (1 critical)
      Gitleaks: 1 finding (1 critical)

[3/4] Gate evaluation
      BLOCKED: max_critical_findings violated — found 3, limit 0

[4/4] Risk assessment
      Risk score: 8.4/10
      Mode: static (no Bedrock configured)

Report saved: controls/products/payment-api/risk-assessments/RA-2026-0419-001.yaml
Findings logged: output/findings.jsonl (7 entries)
```

### 8-5. 테스트

`tests/unit/test_cli.py`:
- `test_cli_help` — `python -m orchestrator --help` 실행 시 도움말 출력
- `test_init_creates_manifest` — init 명령이 YAML 파일 생성 (click.testing.CliRunner 사용)
- `test_assess_exit_code_0_on_pass` — gate pass → exit code 0
- `test_assess_exit_code_1_on_fail` — gate fail → exit code 1
- `test_export_creates_json` — export 명령이 JSON 파일 생성
- `test_detect_finds_matches` — detect 명령이 Sigma 매칭 결과 출력

모든 테스트에서 scanner는 mock한다 (실제 CLI 실행 X). CliRunner를 사용하여 CLI 테스트.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint && python -m orchestrator --help
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `python -m orchestrator --help`가 모든 command를 보여주는지 확인.
3. 각 command가 올바른 컴포넌트를 호출하는지 테스트로 확인.
4. CLI가 thin wrapper인지 확인 — 비즈니스 로직은 이전 step의 모듈에 있어야 한다.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- CLI에 비즈니스 로직을 넣지 마라. 이유: CLI는 thin wiring layer. 로직은 이전 step의 모듈에 있다.
- 새로운 비즈니스 로직 클래스를 만들지 마라. 이유: 이미 모든 컴포넌트가 구현되어 있다.
- 실제 scanner CLI를 테스트에서 실행하지 마라. mock을 사용하라.
- interactive prompt를 테스트하기 어렵게 만들지 마라. click.testing.CliRunner의 input 파라미터를 활용하라.
