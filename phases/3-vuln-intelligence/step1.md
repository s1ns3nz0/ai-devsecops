# Step 1: vuln-enrichment

## 읽어야 할 파일

- `/orchestrator/intelligence/epss.py` — Step 0의 EPSS client
- `/orchestrator/scanners/grype.py` — Grype scanner (CVE findings)
- `/orchestrator/types.py` — Finding dataclass
- `/orchestrator/scanners/control_mapper.py` — Control ID mapping
- `/controls/baselines/pci-dss-4.0.yaml` — compliance context

## 작업

### 1-1. EnrichedVulnerability 모델

`orchestrator/intelligence/models.py`:

```python
@dataclass
class EnrichedVulnerability:
    """CVE finding enriched with exploit intelligence."""
    cve_id: str
    severity: str                    # from Grype (CVSS-based)
    epss_score: float | None         # exploit probability (0-1)
    epss_percentile: float | None    # position vs all CVEs
    package: str                     # affected package name
    installed_version: str           # version in use
    fixed_version: str               # version that fixes it
    file_path: str                   # where in the codebase
    control_ids: list[str]           # compliance controls affected
    priority: str                    # computed: critical/high/medium/low

    # Context for AI analysis (Step 2)
    product_context: str             # "payment-api, PCI scope, internet-facing"
    data_classification: list[str]   # ["PCI", "PII-financial"]
```

### 1-2. Vulnerability Enricher

`orchestrator/intelligence/enricher.py`:

```python
class VulnerabilityEnricher:
    """Enriches Grype CVE findings with EPSS scores and compliance context.

    Takes raw Grype findings and produces EnrichedVulnerability objects with:
    - EPSS exploit probability
    - Compliance control mapping
    - Priority scoring (EPSS × CVSS × compliance context)
    - Product context for AI analysis
    """

    def __init__(self, epss_client: EpssClient, control_mapper: ControlMapper): ...

    def enrich(
        self,
        findings: list[Finding],
        manifest: ProductManifest,
    ) -> list[EnrichedVulnerability]:
        """
        Enrich Grype findings with exploit intelligence.

        Priority scoring:
        - CRITICAL: EPSS > 0.5 OR (CVSS critical AND PCI scope)
        - HIGH: EPSS > 0.1 OR CVSS high
        - MEDIUM: EPSS > 0.01
        - LOW: EPSS <= 0.01 or unavailable
        """
        ...

    def sort_by_priority(self, vulns: list[EnrichedVulnerability]) -> list[EnrichedVulnerability]:
        """Sort by EPSS (descending), then CVSS severity."""
        ...
```

### 1-3. 테스트

`tests/unit/test_vuln_enrichment.py`:
- `test_enrich_adds_epss_score` — EPSS 점수가 추가되는지 확인
- `test_priority_critical_when_epss_high` — EPSS > 0.5 → priority=critical
- `test_priority_low_when_epss_unavailable` — EPSS None → priority는 CVSS 기반
- `test_enrich_preserves_control_ids` — Control ID 매핑 유지
- `test_sort_by_priority` — EPSS 내림차순 정렬
- `test_pci_scope_elevates_priority` — PCI scope + CVSS critical → priority=critical (EPSS 없어도)

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- Gate 결정에 EPSS를 직접 사용하지 마라. 이 step은 enrichment만. Gate는 기존 ThresholdEvaluator가 처리.
- Grype scanner를 수정하지 마라. Enricher는 Grype 결과를 받아서 보강.
