# Step 2: scanner-integration

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "Gate Path" 섹션, Scanner 목록
- `/docs/ADR.md` — ADR-003 (gate path 100% 로컬), ADR-005 (Grype gates, DT enriches)
- `/orchestrator/types.py` — Finding dataclass
- `/orchestrator/controls/repository.py` — ControlsRepository (verification_methods 매핑)
- `/orchestrator/controls/models.py` — Control, VerificationMethod
- `/controls/baselines/*.yaml` — verification_methods에 정의된 scanner rule 매핑

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 2-1. Scanner Protocol

`orchestrator/scanners/base.py`:

```python
class Scanner(Protocol):
    """모든 scanner wrapper가 구현하는 인터페이스."""

    @property
    def name(self) -> str: ...

    def scan(self, target_path: str) -> list[Finding]: ...

    def parse_output(self, raw_output: str) -> list[Finding]: ...
```

### 2-2. Control ID Mapper

`orchestrator/scanners/control_mapper.py`:

```python
class ControlMapper:
    """Scanner finding을 Control ID로 매핑한다.

    매핑 소스는 Controls Repository의 verification_methods 필드.
    이 매핑은 deterministic — AI가 관여하지 않는다.
    """

    def __init__(self, controls_repo: ControlsRepository): ...

    def map_finding(self, source: str, rule_id: str) -> list[str]:
        """
        scanner name + rule_id → 해당하는 Control ID 목록.
        매핑이 없으면 빈 리스트 반환 (unmapped finding).
        """
        ...
```

### 2-3. Scanner Wrappers

각 scanner wrapper는 Scanner protocol을 구현한다. **실제 CLI를 subprocess로 호출**하되, unit 테스트에서는 recorded output fixture를 사용한다.

각 scanner의 constructor에 `ControlMapper`를 주입한다:

```python
class CheckovScanner:
    def __init__(self, control_mapper: ControlMapper): ...
    def scan(self, target_path: str) -> list[Finding]: ...
    def parse_output(self, raw_output: str) -> list[Finding]: ...
```

`parse_output()`에서 각 finding 생성 시 `self.control_mapper.map_finding()`을 호출하여 `control_ids`를 설정한다.

**`orchestrator/scanners/checkov.py`**:
- `scan()`: `checkov -d {target} --output json --quiet` 실행
- `parse_output()`: Checkov JSON 출력에서 failed checks 추출 → Finding 생성
- severity 매핑: CRITICAL/HIGH/MEDIUM/LOW (Checkov의 severity 필드)

**`orchestrator/scanners/semgrep.py`**:
- `scan()`: `semgrep scan --json --quiet {target}` 실행
- `parse_output()`: Semgrep JSON 출력에서 results 추출 → Finding 생성
- rule_id: `check_id` 필드 (e.g., `python.lang.security.injection.sql-injection`)

**`orchestrator/scanners/grype.py`**:
- `scan()`: `grype {target} -o json` 실행
- `parse_output()`: Grype JSON 출력에서 matches 추출 → Finding 생성
- severity 매핑: Grype의 vulnerability.severity 필드

**`orchestrator/scanners/gitleaks.py`**:
- `scan()`: `gitleaks detect --source {target} --report-format json --report-path -` 실행
- `parse_output()`: Gitleaks JSON 출력 파싱 → Finding 생성
- severity: 모든 secret finding은 "critical"

각 wrapper에서 `ControlMapper`를 사용하여 finding에 `control_ids`를 설정한다.

### 2-4. Scanner Runner

`orchestrator/scanners/runner.py`:

```python
class ScannerRunner:
    """모든 scanner를 실행하고 결과를 집계한다."""

    def __init__(self, scanners: list[Scanner]): ...
    # 각 scanner는 이미 ControlMapper를 가지고 있으므로 runner에는 불필요

    def run_all(self, target_path: str) -> list[Finding]:
        """
        모든 scanner를 순차 실행. 각 scanner 실패 시 에러 로깅 후 계속 진행.
        MVP-0 failure policy: log and continue.
        """
        ...
```

### 2-5. Test Fixtures

`tests/fixtures/scanner-outputs/` 디렉토리를 생성하고 각 scanner의 실제 JSON 출력을 기록한다:

- `checkov_output.json` — 2-3개 failed checks 포함
- `semgrep_output.json` — 2-3개 findings 포함 (SQL injection, hardcoded secret)
- `grype_output.json` — 2-3개 vulnerabilities 포함 (critical CVE 1개)
- `gitleaks_output.json` — 1-2개 secret findings 포함

각 fixture는 해당 scanner의 실제 출력 형식을 정확히 따른다. 문서를 참조하여 정확한 JSON 구조를 사용하라.

### 2-6. 테스트

`tests/unit/test_scanners.py`:

각 scanner wrapper의 `parse_output()` 테스트:
- `test_checkov_parse_output` — fixture → Finding 변환 검증
- `test_semgrep_parse_output` — fixture → Finding 변환 검증
- `test_grype_parse_output` — fixture → Finding 변환 검증
- `test_gitleaks_parse_output` — fixture → Finding 변환 검증

각 finding에 `control_ids`가 올바르게 매핑되는지 검증:
- `test_checkov_finding_has_control_ids` — CKV_AWS_19 → Controls Repository에 정의된 control ID 매핑 확인 (step1의 baselines YAML 참조)
- `test_semgrep_finding_has_control_ids` — sql-injection rule → PCI-DSS-6.3.1 매핑
- `test_unmapped_rule_returns_empty_control_ids` — 매핑 없는 rule → [] 반환

`tests/unit/test_control_mapper.py` (실제 `controls/baselines/*.yaml` 파일을 로드하여 테스트):
- `test_map_known_rule` — 알려진 rule → control IDs 반환
- `test_map_unknown_rule` — 모르는 rule → 빈 리스트 반환
- `test_map_rule_to_multiple_controls` — 하나의 rule이 여러 control에 매핑

`tests/unit/test_scanner_runner.py`:
- `test_run_all_aggregates_findings` — 여러 scanner 결과가 합쳐지는지 검증 (scanner를 mock하여 테스트)
- `test_scanner_failure_does_not_stop_others` — 하나의 scanner가 실패해도 나머지 실행

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 모든 scanner의 `parse_output()` 테스트가 통과하는지 확인한다.
3. Control ID 매핑이 Controls Repository의 verification_methods와 일치하는지 확인한다.
4. CRITICAL 규칙 확인: scanner는 로컬 CLI 도구이며, MCP나 외부 서비스를 사용하지 않는지 확인한다.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- 실제 scanner CLI를 unit 테스트에서 실행하지 마라. 이유: CI 환경에서 scanner가 설치되어 있지 않을 수 있다. `parse_output()` 테스트는 fixture 파일만 사용한다.
- `scan()` 메서드의 subprocess 호출을 unit 테스트에서 실행하지 마라. 이유: 실제 스캔은 integration test이다.
- Finding의 `control_ids`를 하드코딩하지 마라. 이유: ControlMapper를 통해 Controls Repository에서 동적으로 매핑해야 한다.
- DefectDojo나 Dependency-Track에 findings를 전송하지 마라. 이유: MVP-0에서는 JSONL만 사용한다 (Step 6).
