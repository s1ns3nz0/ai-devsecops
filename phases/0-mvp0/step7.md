# Step 7: sigma-engine

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "Detection" 관련
- `/docs/ADR.md` — ADR-007 (Custom Python Sigma Engine)
- `/docs/PRD.md` — "Detection Engine" 관련
- `/orchestrator/types.py` — Finding

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

### 7-1. Sigma Rule Model

`orchestrator/sigma/models.py`:

```python
@dataclass
class SigmaRule:
    """Sigma rule의 Python 표현."""
    id: str
    title: str
    description: str
    status: str                      # "experimental", "test", "stable"
    level: str                       # "critical", "high", "medium", "low", "informational"
    logsource: dict                  # category, product 등
    detection: dict                  # 검출 조건
    tags: list[str]                  # ATT&CK IDs: ["attack.t1110", "attack.brute_force"]
    control_ids: list[str]           # ["PCI-DSS-10.2.1", "FISC-SAFETY-15"]

@dataclass
class SigmaMatch:
    """Sigma rule 매칭 결과."""
    rule: SigmaRule
    log_entry: dict
    matched_at: str                  # ISO timestamp

    def to_finding(self, product: str = "") -> Finding:
        """SigmaMatch를 Finding으로 변환. Evidence chain 연결용."""
        ...
```

### 7-2. Sigma Engine

`orchestrator/sigma/engine.py`:

```python
class SigmaEngine:
    """
    Custom Python Sigma matcher (~150 LOC 목표).

    지원 범위 (MVP-0):
    - field 값 일치 (equals)
    - field 값 포함 (contains, startswith, endswith)
    - AND/OR 조합 (detection.condition에서 "and", "or")
    - selection 참조 (detection.selection → detection.condition: selection)

    미지원 (future):
    - aggregation (count, sum 등)
    - near operator
    - timeframe
    - regex (정규식 매칭)
    """

    def __init__(self, rules_dir: str): ...

    def load_rules(self) -> list[SigmaRule]:
        """rules_dir에서 모든 .yml 파일을 로드한다."""
        ...

    def evaluate(self, log_entry: dict) -> list[SigmaMatch]:
        """단일 log entry를 모든 로드된 rule에 대해 평가한다."""
        ...

    def evaluate_log_file(self, log_path: str) -> list[SigmaMatch]:
        """JSON log 파일의 각 라인을 evaluate한다 (JSONL 형식)."""
        ...

    def _match_detection(self, detection: dict, condition: str, log_entry: dict) -> bool:
        """detection 블록의 condition을 log entry에 대해 평가한다."""
        ...

    def _match_selection(self, selection: dict, log_entry: dict) -> bool:
        """단일 selection 블록을 평가한다."""
        ...
```

### 7-3. Sigma Rules (3-5개)

`sigma/rules/` 디렉토리에 YAML 형식의 Sigma rule을 생성한다:

**`sigma/rules/brute_force_login.yml`**:
```yaml
title: Brute Force Login Attempt
id: bf-001
status: stable
level: high
description: Detects multiple failed login attempts from the same IP
logsource:
  category: application
  product: payment-api
detection:
  selection:
    event_type: login_failed
  condition: selection
tags:
  - attack.t1110
  - attack.brute_force
control_ids:
  - PCI-DSS-10.2.1
  - FISC-SAFETY-15
```

**`sigma/rules/sql_injection_attempt.yml`**:
```yaml
title: SQL Injection Attempt
id: sqli-001
status: stable
level: high
logsource:
  category: application
  product: payment-api
detection:
  selection:
    event_type: api_request
    path|contains:
      - "OR 1=1"
      - "UNION SELECT"
      - "DROP TABLE"
      - "' OR '"
  condition: selection
tags:
  - attack.t1190
control_ids:
  - PCI-DSS-6.3.1
  - ASVS-V5.3.4
```

`|contains` modifier는 field 값에 해당 문자열이 포함되어 있는지 검사한다. engine의 `_match_selection`에서 구현.

**`sigma/rules/data_exfiltration.yml`**:
- event_type: data_export (단순 field 매칭, 수치 비교 없음)
- ATT&CK: T1048
- Control: PCI-DSS-10.2.1

**`sigma/rules/privilege_escalation.yml`**:
- event_type: role_change 또는 admin_access
- ATT&CK: T1078
- Control: FISC-ACCESS-07

### 7-4. Sample Log Fixtures

`tests/fixtures/sample-logs/access.jsonl`:
```jsonl
{"timestamp":"2026-04-19T10:00:00Z","event_type":"api_request","path":"/api/payment","method":"POST","status":200,"ip":"10.0.0.1"}
{"timestamp":"2026-04-19T10:00:01Z","event_type":"login_failed","username":"admin","ip":"192.168.1.100","reason":"invalid_password"}
{"timestamp":"2026-04-19T10:00:02Z","event_type":"login_failed","username":"admin","ip":"192.168.1.100","reason":"invalid_password"}
{"timestamp":"2026-04-19T10:00:03Z","event_type":"api_request","path":"/api/export?id=1 OR 1=1","method":"GET","status":400,"ip":"10.0.0.5"}
{"timestamp":"2026-04-19T10:00:04Z","event_type":"data_export","username":"user1","records_count":50000,"ip":"10.0.0.2"}
{"timestamp":"2026-04-19T10:00:05Z","event_type":"login_success","username":"admin","ip":"192.168.1.100"}
```

### 7-5. 테스트

`tests/unit/test_sigma_engine.py`:
- `test_load_rules` — 4개 rule YAML 로드 확인
- `test_match_brute_force` — login_failed 이벤트 → brute_force rule 매칭
- `test_match_sql_injection` — SQL 키워드 포함 path → sql_injection rule 매칭
- `test_no_match_normal_request` — 정상 요청 → 매칭 없음
- `test_match_returns_sigma_match` — SigmaMatch에 rule, log_entry, timestamp 포함
- `test_evaluate_log_file` — fixture 로그 파일 → 여러 매칭 결과
- `test_rule_has_control_ids` — 매칭된 rule에 control_ids 포함
- `test_rule_has_attack_tags` — 매칭된 rule에 ATT&CK tag 포함
- `test_sigma_match_to_finding` — SigmaMatch.to_finding()이 올바른 Finding 반환 (source="sigma", control_ids 포함)
- `test_contains_modifier` — `path|contains` 매칭 테스트

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. Sigma engine이 ~150 LOC 이내인지 확인한다 (models.py 제외).
3. 4개의 Sigma rule이 올바른 YAML 형식인지 확인한다.
4. 각 rule에 ATT&CK tag와 Control ID가 포함되는지 확인한다.
5. 결과에 따라 `phases/0-mvp0/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "생성된 파일과 핵심 결정을 한 줄로 요약"`
   - 실패 시: `"status": "error"`, `"error_message": "구체적 에러 내용"`

## 금지사항

- Wazuh, chainsaw, sigma-cli 등 외부 Sigma 도구를 사용하지 마라. 이유: ADR-007. Custom Python 구현.
- aggregation, near, timeframe 같은 고급 Sigma 기능을 구현하지 마라. 이유: MVP-0는 기본 field matching만.
- 150 LOC를 크게 초과하지 마라 (engine.py 기준). 이유: 복잡한 Sigma 엔진은 이 프로젝트의 목적이 아니다.
- 실제 SIEM이나 외부 서비스에 연결하지 마라.
