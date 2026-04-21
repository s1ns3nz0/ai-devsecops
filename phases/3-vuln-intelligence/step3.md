# Step 3: cli-integration

## 읽어야 할 파일

- `/orchestrator/cli.py` — 기존 commands
- `/orchestrator/intelligence/epss.py` — EPSS client (Step 0)
- `/orchestrator/intelligence/enricher.py` — VulnerabilityEnricher (Step 1)
- `/orchestrator/intelligence/threat_model.py` — ThreatModel + StaticThreatModelGenerator (Step 2)
- `/orchestrator/scanners/grype.py` — Grype findings
- `/orchestrator/scanners/sbom.py` — SBOM components

## 작업

### 3-1. `threat-model` CLI Command

```python
@cli.command("threat-model")
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--output", default="output", help="Output directory")
def threat_model_cmd(target_path: str, product: str, output: str) -> None:
    """Generate threat model from real application components.

    Analyzes SBOM components + CVEs + product context to produce
    a threat model with concrete attack scenarios.

    Flow:
    1. Generate SBOM (real components)
    2. Scan with Grype (known CVEs)
    3. Enrich with EPSS (exploit probability)
    4. Generate threat model (static mode)
    5. Output YAML threat model
    """
    ...
```

### 3-2. CLI Output

```
$ python -m orchestrator threat-model ./sample-app --product payment-api

[1/4] SBOM generation
      Components: 132 (51 Python, 1 Go, 80 other)

[2/4] Vulnerability scan + EPSS enrichment
      CVEs found: 16
      EPSS enriched: 14/16
      CRITICAL (EPSS > 0.5): 2
      HIGH (EPSS > 0.1): 3

[3/4] Threat model generation
      Mode: static
      Attack surface: internet-facing API, PCI data, external payment gateway
      Threat actors: 1
      Threat scenarios: 5

[4/4] Controls gap analysis
      Required by threat model: 8 controls
      Currently covered: 6 controls
      Gap: 2 controls
        - ASVS-V3.5.1: JWT revocation
        - PCI-DSS-8.3.6: Password policy

Threat model saved: output/threat-model-payment-api.yaml
```

### 3-3. ADR 추가

`docs/ADR.md`에 ADR-011 추가:

```
### ADR-011: Component-Based Threat Modeling with EPSS
**결정**: SBOM 컴포넌트 + EPSS enriched CVEs + product manifest를 기반으로 위협 모델 자동 생성. Static mode (template 기반) 먼저 구현, AI mode는 이후 추가.
**이유**: 위협 모델이 실제 애플리케이션 컴포넌트에 기반하면 추상적인 위협 목록이 아닌 구체적인 공격 시나리오를 도출할 수 있음. EPSS로 실제 exploit 가능성을 반영.
**트레이드오프**: Static mode는 template 기반이므로 컨텍스트 깊이가 제한적. AI mode 추가 시 Bedrock 비용 발생.
```

### 3-4. 테스트

`tests/unit/test_threat_model_cli.py`:
- `test_threat_model_help` — command help 출력
- `test_threat_model_produces_yaml` — output 디렉토리에 YAML 생성
- `test_threat_model_contains_scenarios` — 위협 시나리오 포함
- `test_threat_model_contains_controls_gap` — 컨트롤 gap 분석 포함

Scanner + EPSS는 mock. 실제 CLI 실행 없음.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint && python -m orchestrator threat-model --help
```

## 금지사항

- AI/Bedrock를 호출하지 마라. Static mode만.
- 실제 scanner CLI를 테스트에서 실행하지 마라.
- 기존 commands (assess, scan, etc.)를 수정하지 마라.
- Gate 결정에 threat model을 사용하지 마라.
