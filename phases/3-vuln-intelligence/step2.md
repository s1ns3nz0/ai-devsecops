# Step 2: threat-model-format

## 읽어야 할 파일

- `/CLAUDE.md`
- `/orchestrator/types.py` — 기존 dataclasses
- `/orchestrator/scanners/sbom.py` — SbomResult (실제 컴포넌트 목록)
- `/controls/products/payment-api/product-manifest.yaml` — 제품 정의
- `/orchestrator/intelligence/models.py` — Step 1의 EnrichedVulnerability

## 작업

### 2-1. Threat Model Data Format

`orchestrator/intelligence/threat_model.py`:

AI가 실제 애플리케이션 컴포넌트를 기반으로 threat modeling을 수행하기 위한 데이터 모델을 정의한다. AI 구현은 이후에 추가 — 이 step은 **format만 정의**.

```python
@dataclass
class ThreatActor:
    """위협 행위자."""
    id: str                      # TA-001
    name: str                    # "External Attacker"
    motivation: str              # "Financial gain"
    capability: str              # "moderate" | "high" | "nation-state"
    attack_surface: list[str]    # ["internet-facing API", "supply chain"]

@dataclass
class ThreatScenario:
    """구체적인 위협 시나리오."""
    id: str                      # TS-001
    title: str                   # "JWT token forgery via weak signing"
    actor: str                   # TA-001 reference
    attack_vector: str           # STRIDE category: S/T/R/I/D/E
    mitre_technique: str         # ATT&CK: T1190, T1078, etc.
    target_component: str        # 실제 컴포넌트: "PyJWT 1.7.1" or "src/app.py:login"
    preconditions: list[str]     # ["Network access to API", "Knowledge of HS256 usage"]
    attack_steps: list[str]      # ["Intercept JWT", "Exploit HS256 confusion", "Forge admin token"]
    impact: str                  # "Full access to payment processing"
    likelihood: str              # "high" — based on EPSS + exposure
    severity: str                # "critical"
    affected_controls: list[str] # ["PCI-DSS-3.5.1", "ASVS-V3.5.3"]
    mitigation: str              # "Upgrade PyJWT>=2.4.0, enforce RS256"

@dataclass
class ThreatModel:
    """애플리케이션 위협 모델 — AI가 실제 컴포넌트 기반으로 생성."""
    product: str
    generated_at: str
    mode: str                    # "ai" | "static"

    # 입력 (AI에 제공되는 컨텍스트)
    components: list[str]        # SBOM에서 추출한 실제 컴포넌트 목록
    architecture: dict           # product manifest (deployment, integrations)
    data_classification: list[str]
    known_vulnerabilities: list[str]  # enriched CVEs

    # 출력 (AI가 생성)
    threat_actors: list[ThreatActor]
    threat_scenarios: list[ThreatScenario]
    attack_surface_summary: str
    risk_summary: str

    # 컨트롤 매핑
    controls_required: list[str]     # 위협 시나리오에서 도출된 필요 컨트롤
    controls_covered: list[str]      # 현재 스캔으로 커버되는 컨트롤
    controls_gap: list[str]          # 추가 필요한 컨트롤
```

### 2-2. Static Threat Model Generator

AI 없이 동작하는 static threat model 생성기. SBOM + manifest + enriched CVEs를 기반으로 template 위협 모델을 생성.

```python
class StaticThreatModelGenerator:
    """Static threat model — AI 없이 컴포넌트 기반으로 위협 시나리오 생성.

    SBOM 컴포넌트 + EPSS enriched CVEs + product manifest를 분석하여
    template 기반 위협 시나리오를 생성.

    Example:
      SBOM에 PyJWT 1.7.1이 있고, CVE-2022-29217 (EPSS 0.234)가 있으면:
      → ThreatScenario: "JWT token forgery via algorithm confusion"
      → target_component: "PyJWT 1.7.1"
      → mitre_technique: "T1078" (Valid Accounts)
      → affected_controls: ["ASVS-V3.5.3"]
    """

    def generate(
        self,
        manifest: ProductManifest,
        sbom_components: list[str],
        enriched_vulns: list[EnrichedVulnerability],
        controls: list[Control],
    ) -> ThreatModel:
        """
        Static threat model 생성:
        1. SBOM 컴포넌트에서 카테고리 추출 (web framework, crypto, DB, etc.)
        2. Enriched CVEs에서 실제 위협 시나리오 도출
        3. Product manifest에서 공격 표면 분석
        4. Controls gap 계산
        """
        ...

    def _identify_attack_surface(self, manifest: ProductManifest) -> list[str]:
        """Product manifest에서 공격 표면 식별.
        예: internet-facing, external integrations, PCI data handling
        """
        ...

    def _generate_scenarios_from_vulns(
        self, enriched_vulns: list[EnrichedVulnerability]
    ) -> list[ThreatScenario]:
        """Enriched CVEs에서 구체적 위협 시나리오 도출.
        EPSS > 0.1인 CVE마다 시나리오 생성.
        """
        ...

    def _map_to_mitre(self, vuln: EnrichedVulnerability) -> str:
        """CVE 타입 → MITRE ATT&CK technique 매핑.
        예: SQL injection → T1190, credential theft → T1078
        """
        ...
```

### 2-3. Threat Model 출력 포맷 (YAML)

`output/threat-model-payment-api.yaml`:

```yaml
threat_model:
  product: payment-api
  generated_at: "2026-04-22T10:00:00Z"
  mode: static

  attack_surface:
    - internet-facing API (5 endpoints)
    - external payment gateway integration
    - PCI cardholder data handling
    - AWS EKS deployment (ap-northeast-1)

  threat_actors:
    - id: TA-001
      name: External Attacker
      motivation: Financial gain
      capability: moderate
      attack_surface: [internet-facing API, supply chain]

  threat_scenarios:
    - id: TS-001
      title: JWT token forgery via algorithm confusion
      actor: TA-001
      attack_vector: Spoofing (STRIDE-S)
      mitre_technique: T1078
      target_component: "PyJWT 1.7.1 (CVE-2022-29217, EPSS: 0.234)"
      preconditions:
        - Network access to /api/login
        - Knowledge that HS256 is used
      attack_steps:
        - Obtain a valid JWT token
        - Exploit algorithm confusion (HS256 → none)
        - Forge admin token with arbitrary claims
      impact: Full access to payment processing
      likelihood: high
      severity: critical
      affected_controls: [ASVS-V3.5.3, PCI-DSS-8.3.1]
      mitigation: "pip install PyJWT>=2.4.0; enforce algorithm whitelist"

  controls_gap:
    - ASVS-V3.5.1: "No scanner covers JWT revocation"
    - PCI-DSS-8.3.6: "Password policy not verifiable by SAST"

  risk_summary: |
    Payment API has 3 CRITICAL threat scenarios based on 132 SBOM components
    and 16 known CVEs. Primary risk: JWT token forgery + credential exposure.
```

### 2-4. 테스트

`tests/unit/test_threat_model.py`:
- `test_threat_model_dataclass` — ThreatModel 생성 + 필드 확인
- `test_threat_scenario_has_mitre` — 시나리오에 ATT&CK technique 포함
- `test_static_generator_from_vulns` — enriched CVE → 위협 시나리오 생성
- `test_static_generator_identifies_attack_surface` — manifest → 공격 표면
- `test_controls_gap_calculated` — 필요 컨트롤 vs 커버 컨트롤 gap
- `test_output_yaml_format` — YAML 출력 포맷 검증

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 금지사항

- Bedrock/AI를 호출하지 마라. 이 step은 format + static generator만.
- Gate 결정에 threat model을 사용하지 마라. Threat model은 정보 제공.
- 실제 EPSS API를 호출하지 마라. 테스트에서 mock 사용.
