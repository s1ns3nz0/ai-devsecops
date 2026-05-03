# Step 1: scanner-mapper

## 읽어야 할 파일

- `/orchestrator/importer/oscal.py` — Step 0의 ImportedControl, BaselineGenerator
- `/orchestrator/controls/models.py` — VerificationMethod
- `/orchestrator/scanners/control_mapper.py` — 기존 scanner mapping 패턴
- `/controls/baselines/pci-dss-4.0.yaml` — 매핑 예시

## 작업

### 1-1. Scanner Suggestion Engine

`orchestrator/importer/suggest.py`를 생성한다:

```python
class ScannerSuggester:
    """컨트롤 키워드 기반으로 scanner mapping을 제안.

    이 모듈은 AI가 아닌 키워드 매칭 기반.
    제안일 뿐이며, 인간이 반드시 검토해야 함.

    매핑 전략:
    1. 컨트롤 title/description에서 키워드 추출
    2. 키워드 → scanner 카테고리 매핑
    3. scanner 카테고리 → 구체적 rules/check_ids 제안
    """

    # 키워드 → scanner 매핑 테이블
    KEYWORD_MAP: dict[str, list[dict[str, object]]] = {
        # Access Control keywords
        "access control": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_1", "CKV_AWS_40", "CKV_AWS_61"]},
        ],
        "authentication": [
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
            {"scanner": "gitleaks"},
        ],
        "password": [
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
            {"scanner": "gitleaks"},
        ],
        # Encryption keywords
        "encrypt": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_19", "CKV_AWS_145"]},
            {"scanner": "semgrep", "rules": ["python.cryptography.security.*"]},
        ],
        "cryptograph": [
            {"scanner": "semgrep", "rules": ["python.cryptography.security.*", "python.lang.security.audit.weak-hashing.*"]},
        ],
        # Network keywords
        "network": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_150"]},
        ],
        "firewall": [
            {"scanner": "checkov", "check_ids": ["CKV_AWS_24", "CKV_AWS_260"]},
        ],
        # Vulnerability management
        "vulnerability": [
            {"scanner": "grype", "severity_threshold": "high"},
            {"scanner": "sbom"},
        ],
        "patch": [
            {"scanner": "grype", "severity_threshold": "high"},
        ],
        "software component": [
            {"scanner": "sbom"},
            {"scanner": "grype", "severity_threshold": "medium"},
        ],
        # Logging / monitoring
        "audit": [
            {"scanner": "sigma"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_67", "CKV_AWS_18"]},
        ],
        "log": [
            {"scanner": "sigma"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_67", "CKV_AWS_35"]},
        ],
        "monitor": [
            {"scanner": "sigma"},
        ],
        "detect": [
            {"scanner": "sigma"},
        ],
        # Input validation
        "input validation": [
            {"scanner": "semgrep", "rules": ["python.lang.security.injection.*"]},
        ],
        "injection": [
            {"scanner": "semgrep", "rules": ["python.lang.security.injection.*", "python.lang.security.audit.formatted-sql-query.*"]},
        ],
        # Secrets
        "credential": [
            {"scanner": "gitleaks"},
            {"scanner": "semgrep", "rules": ["python.lang.security.audit.hardcoded-password.*"]},
        ],
        "secret": [
            {"scanner": "gitleaks"},
        ],
        "key management": [
            {"scanner": "gitleaks"},
            {"scanner": "checkov", "check_ids": ["CKV_AWS_33"]},
        ],
    }

    def suggest(self, control: ImportedControl) -> list[dict[str, object]]:
        """컨트롤의 title + description에서 키워드를 매칭하여 scanner 제안.

        Returns: 제안된 verification_methods 리스트.
        제안은 best-effort — 인간 검토 필요.
        """
        ...

    def apply_suggestions(
        self,
        controls: list[ImportedControl],
        output_path: str,
    ) -> tuple[int, int]:
        """컨트롤 리스트에 제안을 적용하여 YAML 업데이트.

        Returns: (제안된 컨트롤 수, 제안 없는 컨트롤 수)
        제안 없는 컨트롤은 verification_methods: [] 유지.
        """
        ...
```

### 1-2. 테스트

`tests/unit/test_scanner_suggester.py`:
- `test_access_control_suggests_checkov` — "access control" → checkov IAM checks
- `test_encryption_suggests_checkov_and_semgrep` — "encrypt" → checkov + semgrep crypto
- `test_vulnerability_suggests_grype` — "vulnerability" → grype
- `test_logging_suggests_sigma` — "audit log" → sigma
- `test_no_keyword_match_returns_empty` — "physical security" → [] (매핑 불가)
- `test_multiple_keywords_merged` — "authentication and encryption" → gitleaks + checkov + semgrep
- `test_apply_suggestions_updates_yaml` — YAML 파일에 제안 적용

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- AI/Bedrock를 사용하지 마라. 키워드 매칭만.
- 제안을 "확정"으로 표시하지 마라. 모든 출력에 "suggested — review required" 라벨.
- 기존 baseline YAML을 수정하지 마라.
