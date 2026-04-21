# Step 5: defectdojo-client

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md` — ADR-008 (Evidence는 generated artifact)
- `/orchestrator/evidence/jsonl.py` — JSONL writer (현재 evidence storage)
- `/orchestrator/types.py` — Finding
- `/docker-compose.yml` — DefectDojo 설정 (Step 4)

## 작업

### 5-1. DefectDojo API Client

`orchestrator/integrations/defectdojo.py`를 생성한다:

```python
class DefectDojoClient:
    """DefectDojo REST API client.

    핵심 규칙:
    - Evidence path에서만 사용 (ADR-003). Gate path에 영향 없음.
    - DefectDojo가 다운되어도 gate는 동작 (JSONL이 백업).
    - Finding hash로 idempotent import (Red Team RT-28).
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", api_key: str = ""): ...

    def health_check(self) -> bool:
        """DefectDojo가 사용 가능한지 확인."""
        ...

    def get_or_create_product(self, name: str, description: str = "") -> int:
        """Product를 찾거나 생성하고 product_id를 반환."""
        ...

    def get_or_create_engagement(self, product_id: int, name: str) -> int:
        """Engagement를 찾거나 생성하고 engagement_id를 반환."""
        ...

    def import_findings(self, engagement_id: int, findings: list[Finding], scan_type: str = "Generic Findings Import") -> dict:
        """Findings를 DefectDojo에 import.

        idempotent: hash_code 기반 dedup (DefectDojo 내장 기능).
        각 finding의 control_ids를 tags로 추가.
        """
        ...

    def get_findings(self, product_name: str, tags: list[str] | None = None) -> list[dict]:
        """Product의 findings를 조회. tags로 control_id 필터링."""
        ...
```

### 5-2. Finding → DefectDojo 변환

```python
def finding_to_defectdojo(finding: Finding) -> dict:
    """Finding 객체를 DefectDojo API import 형식으로 변환.

    DefectDojo Generic Findings Import format:
    {
        "title": rule_id,
        "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
        "description": message,
        "file_path": file,
        "line": line,
        "tags": control_ids,  # Control ID가 tag로 저장됨
        "hash_code": hash(source + file + line + rule_id),
    }
    """
    ...
```

### 5-3. CLI에 DefectDojo sync 추가

`orchestrator/cli.py`에 `sync` command를 추가:

```python
@cli.command()
@click.option("--product", required=True)
@click.option("--defectdojo-url", default="http://127.0.0.1:8080")
@click.option("--api-key", envvar="DD_API_KEY")
@click.option("--jsonl-path", default=None)
def sync(product: str, defectdojo_url: str, api_key: str, jsonl_path: str | None) -> None:
    """Sync JSONL findings to DefectDojo."""
    ...
```

### 5-4. 테스트

`tests/unit/test_defectdojo_client.py`:
- `test_finding_to_defectdojo_format` — 변환 형식 검증
- `test_finding_hash_deterministic` — 같은 finding → 같은 hash
- `test_finding_tags_include_control_ids` — control_ids가 tags에 포함
- `test_health_check_returns_false_when_down` — 연결 실패 시 False

`tests/contract/test_defectdojo_api.py`:
- 녹화된 API 응답으로 client 동작 검증
- `tests/contract/fixtures/defectdojo_product_response.json`
- `tests/contract/fixtures/defectdojo_import_response.json`

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make test-contract && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. DefectDojo API를 실제 호출하지 않는지 확인한다.
3. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- DefectDojo API를 unit 테스트에서 실제 호출하지 마라.
- gate 결정에 DefectDojo를 사용하지 마라. 이유: ADR-003, Evidence path only.
- JSONL writer를 제거하지 마라. DefectDojo는 보강, JSONL은 백업 (Red Team RT-12).
- `requests` 라이브러리를 새로 추가하지 마라. 이유: `urllib.request`를 사용하거나 `httpx`를 추가. 또는 `requests`가 이미 transitive dependency면 사용 가능.
