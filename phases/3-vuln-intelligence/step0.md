# Step 0: epss-client

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md`
- `/orchestrator/scanners/grype.py` — Grype scanner (CVE findings)
- `/orchestrator/types.py` — Finding dataclass

## 작업

### 0-1. EPSS Client

`orchestrator/intelligence/epss.py`를 생성한다:

```python
class EpssClient:
    """EPSS (Exploit Prediction Scoring System) API client.

    EPSS provides the probability that a CVE will be exploited in the wild
    within the next 30 days. Range: 0.0 (unlikely) to 1.0 (very likely).

    API: https://api.first.org/data/v1/epss
    Free, no authentication required, updated daily.

    Why EPSS matters:
    - CVSS 7.5 tells you theoretical severity
    - EPSS 0.67 tells you 67% of similar vulns ARE being exploited
    - Two CVEs with same CVSS can have wildly different EPSS scores
    - This is what helps engineers prioritize 1000 CVEs into 10 urgent ones
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def get_scores(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """
        Batch lookup EPSS scores for a list of CVE IDs.

        API supports up to 100 CVEs per request.
        For larger sets, batch automatically.

        Returns dict: {cve_id: EpssScore}
        """
        ...

    def get_score(self, cve_id: str) -> EpssScore | None:
        """Single CVE lookup."""
        ...

@dataclass
class EpssScore:
    cve: str
    epss: float        # 0.0-1.0 probability of exploitation
    percentile: float  # 0.0-1.0 position relative to all CVEs
    date: str          # date of the EPSS data
```

### 0-2. Offline Fallback

When the EPSS API is unavailable (air-gapped environments), return None gracefully. The platform continues with CVSS-only scoring.

### 0-3. 테스트

`tests/unit/test_epss_client.py`:
- `test_parse_epss_response` — API 응답 JSON 파싱 검증
- `test_batch_lookup` — 여러 CVE 일괄 조회
- `test_unknown_cve_returns_none` — 존재하지 않는 CVE → None
- `test_api_unavailable_returns_empty` — 네트워크 에러 → 빈 dict (graceful)
- `test_epss_score_dataclass` — EpssScore 필드 검증

API 호출은 mock (urllib.request를 mock). 실제 API 호출 없음.

`tests/contract/fixtures/epss_response.json`:
```json
{
  "status": "OK",
  "data": [
    {"cve": "CVE-2023-50782", "epss": "0.67234", "percentile": "0.97123", "date": "2026-04-22"}
  ]
}
```

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- 실제 EPSS API를 unit 테스트에서 호출하지 마라. mock만 사용.
- requests 라이브러리를 추가하지 마라. urllib.request 사용.
- EPSS score를 gate 결정에 직접 사용하지 마라. 이 step은 데이터 수집만.
