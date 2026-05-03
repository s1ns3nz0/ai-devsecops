# Step 0: cia-impact-levels

## 읽어야 할 파일

- `/CLAUDE.md`
- `/orchestrator/types.py` — ProductManifest dataclass
- `/orchestrator/config/schemas/manifest_schema.json` — validation schema
- `/orchestrator/assessor/static.py` — categorize()
- `/controls/products/payment-api/product-manifest.yaml` — sample manifest

## 작업

### 0-1. FIPS 199 Impact Levels in Manifest

`orchestrator/types.py`의 `ProductManifest`에 CIA impact levels 추가:

```python
@dataclass
class ProductManifest:
    name: str
    description: str
    data_classification: list[str]
    jurisdiction: list[str]
    deployment: dict[str, object]
    integrations: list[str] = field(default_factory=list)
    # NEW: FIPS 199 impact levels (RMF Step 2)
    impact_levels: dict[str, str] = field(default_factory=lambda: {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "moderate",
    })
```

impact_levels 값: `"low"` / `"moderate"` / `"high"` (FIPS 199 용어)

### 0-2. Product Manifest 업데이트

`controls/products/payment-api/product-manifest.yaml`에 추가:

```yaml
  impact_levels:
    confidentiality: high      # PCI cardholder data exposure → high
    integrity: high            # Payment amount tampering → high
    availability: moderate     # Service disruption → moderate
```

### 0-3. Schema 업데이트

`manifest_schema.json`에 `impact_levels` 추가:

```json
"impact_levels": {
  "type": "object",
  "properties": {
    "confidentiality": { "type": "string", "enum": ["low", "moderate", "high"] },
    "integrity": { "type": "string", "enum": ["low", "moderate", "high"] },
    "availability": { "type": "string", "enum": ["low", "moderate", "high"] }
  }
}
```

### 0-4. Manifest Loader 업데이트

`orchestrator/config/manifest.py`에서 `impact_levels`를 파싱하여 `ProductManifest`에 포함. 필드가 없으면 기본값 사용 (하위 호환).

### 0-5. Categorize에 CIA 반영

`StaticRiskAssessor.categorize()`에서 CIA impact를 supplementary context로 사용. 기존 framework-count 기반 tier 결정은 유지하되, CIA가 모두 "high"이면 tier를 한 단계 상승 (medium→high, high→critical).

### 0-6. AI 프롬프트에 CIA 포함

`orchestrator/assessor/prompts.py`의 `_format_architecture_context()`에 CIA impact levels 추가:

```
Impact Levels (FIPS 199):
  Confidentiality: HIGH — PCI cardholder data
  Integrity: HIGH — payment amount tampering
  Availability: MODERATE — service disruption
```

### 0-7. 테스트

`tests/unit/test_cia_impact.py`:
- `test_manifest_has_default_impact_levels` — impact_levels 없는 YAML → 기본값
- `test_manifest_parses_impact_levels` — impact_levels 있는 YAML → 파싱
- `test_all_high_cia_elevates_tier` — C/I/A 모두 high → tier 한 단계 상승
- `test_cia_in_architecture_context` — AI 프롬프트에 CIA 포함

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- 기존 manifest 파싱을 깨뜨리지 마라. impact_levels는 optional (하위 호환).
- CIA impact을 gate 결정에 직접 사용하지 마라. Tier 결정의 보조 지표.
