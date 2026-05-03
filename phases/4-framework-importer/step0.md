# Step 0: oscal-parser

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md`
- `/orchestrator/controls/repository.py` — ControlsRepository (출력 대상)
- `/orchestrator/controls/models.py` — Control, VerificationMethod
- `/controls/baselines/pci-dss-4.0.yaml` — 기존 baseline 형식 참조

## 작업

### 0-1. OSCAL Parser

`orchestrator/importer/oscal.py`를 생성한다:

```python
@dataclass
class ImportedControl:
    """OSCAL에서 파싱된 컨트롤 (scanner 매핑 없음)."""
    id: str
    title: str
    description: str
    framework: str
    properties: dict[str, str]  # 추가 메타데이터 (class, family 등)

class OscalParser:
    """NIST OSCAL JSON catalog → ImportedControl 리스트.

    지원 소스:
    1. NIST SP 800-53 Rev 5 OSCAL JSON catalog
    2. NIST SP 800-171 Rev 2 OSCAL JSON (CMMC base)
    3. NIST CSF 2.0 OSCAL JSON
    4. 기타 OSCAL-compatible JSON catalog

    OSCAL JSON 구조:
    {
      "catalog": {
        "groups": [
          {
            "id": "ac",
            "title": "Access Control",
            "controls": [
              {
                "id": "ac-1",
                "title": "Policy and Procedures",
                "parts": [
                  {"name": "statement", "prose": "..."}
                ]
              }
            ]
          }
        ]
      }
    }
    """

    def parse_file(self, path: str, framework_id: str) -> list[ImportedControl]:
        """로컬 OSCAL JSON 파일 파싱."""
        ...

    def parse_url(self, url: str, framework_id: str) -> list[ImportedControl]:
        """URL에서 OSCAL JSON 다운로드 + 파싱."""
        ...

    def _parse_catalog(self, catalog: dict, framework_id: str) -> list[ImportedControl]:
        """OSCAL catalog JSON → ImportedControl 리스트.

        재귀적으로 groups/controls를 탐색.
        controls 내 sub-controls(enhancements)도 포함.
        """
        ...

    def _extract_description(self, control: dict) -> str:
        """parts[name=statement].prose에서 설명 추출."""
        ...
```

### 0-2. Generic JSON/CSV Parser

OSCAL이 아닌 소스 (OWASP ASVS JSON, CIS CSV 등)도 지원:

```python
class GenericFrameworkParser:
    """비-OSCAL 소스 파싱. JSON/CSV 포맷.

    지원:
    - OWASP ASVS JSON (GitHub에서 다운로드)
    - CIS Controls CSV
    - 커스텀 JSON (id, title, description 필드)
    """

    def parse_asvs_json(self, path: str, level: int = 3) -> list[ImportedControl]:
        """OWASP ASVS JSON → ImportedControl.
        level 파라미터로 L1/L2/L3 필터링.
        """
        ...

    def parse_generic_json(
        self,
        path: str,
        framework_id: str,
        id_field: str = "id",
        title_field: str = "title",
        description_field: str = "description",
    ) -> list[ImportedControl]:
        """커스텀 JSON 매핑."""
        ...
```

### 0-3. Baseline YAML Generator

파싱된 컨트롤을 baseline YAML 형식으로 출력:

```python
class BaselineGenerator:
    """ImportedControl 리스트 → baseline YAML 파일.

    출력 형식은 기존 baselines/*.yaml과 동일.
    verification_methods는 비어있음 — 인간이 매핑해야 함.
    """

    def generate(
        self,
        controls: list[ImportedControl],
        output_path: str,
        applicable_tiers: list[str] | None = None,
    ) -> str:
        """YAML 파일 생성. verification_methods: [] (빈 상태).
        Returns: 생성된 파일 경로.
        """
        ...
```

### 0-4. 테스트

`tests/unit/test_oscal_parser.py`:

실제 OSCAL JSON snippet을 fixture로 사용:

`tests/fixtures/oscal/nist-800-53-sample.json`:
```json
{
  "catalog": {
    "uuid": "test-uuid",
    "metadata": {"title": "NIST SP 800-53 Rev 5", "version": "5.0"},
    "groups": [
      {
        "id": "ac",
        "title": "Access Control",
        "controls": [
          {
            "id": "ac-1",
            "title": "Policy and Procedures",
            "parts": [
              {"name": "statement", "prose": "Develop and maintain access control policy."}
            ],
            "props": [
              {"name": "label", "value": "AC-1"}
            ]
          },
          {
            "id": "ac-2",
            "title": "Account Management",
            "parts": [
              {"name": "statement", "prose": "Manage system accounts."}
            ]
          }
        ]
      }
    ]
  }
}
```

테스트:
- `test_parse_oscal_catalog` — 2개 컨트롤 파싱
- `test_control_has_id_title_description` — 필드 정확성
- `test_nested_groups` — 중첩 그룹 처리
- `test_parse_url` — URL 다운로드 mock
- `test_generate_baseline_yaml` — YAML 출력 형식 검증
- `test_generated_yaml_has_empty_verification_methods` — verification_methods: [] 확인
- `test_parse_asvs_json` — ASVS JSON 파싱 (별도 fixture)

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- verification_methods를 자동으로 채우지 마라. 인간이 매핑하는 단계.
- 실제 NIST URL을 테스트에서 다운로드하지 마라. fixture 사용.
- 기존 baselines/*.yaml 파일을 수정하지 마라.
