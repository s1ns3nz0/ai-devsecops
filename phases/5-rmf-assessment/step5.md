# Step 5: cli-integration

## 읽어야 할 파일

- `/orchestrator/cli.py` — 기존 commands
- `/orchestrator/rmf/pipeline.py` — RiskAssessmentPipeline (Step 2)
- `/orchestrator/rmf/sar.py` — SARGenerator (Step 3)
- `/orchestrator/rmf/poam.py` — POAMGenerator, AuthorizationEngine (Step 4)
- `/orchestrator/rmf/models.py` — SP80030Report (Step 1)
- `/docs/ADR.md`

## 작업

### 5-1. `risk-assess` CLI Command

```python
@cli.command("risk-assess")
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--trigger", default="pre_merge")
@click.option("--output", default="output")
@click.option("--format", "fmt", default="yaml", type=click.Choice(["yaml", "json"]))
def risk_assess(target_path: str, product: str, trigger: str, output: str, fmt: str) -> None:
    """Run full NIST SP 800-30 risk assessment with RMF activities.

    Produces:
    1. SP 800-30 Risk Assessment Report
    2. Security Assessment Report (SAR)
    3. Plan of Action & Milestones (POA&M)
    4. Authorization Decision (ATO/DATO/ATO-with-conditions)

    Flow:
    1. Load manifest + profile + controls
    2. Run scanners + EPSS enrichment
    3. AI risk assessment (SP 800-30 4-phase, or static fallback)
    4. Generate SAR (per-control assessment)
    5. Generate POA&M (from findings + risk responses)
    6. Authorization decision
    7. Export all reports to output directory
    """
    ...
```

### 5-2. CLI Output

```
$ python -m orchestrator risk-assess ./sample-app --product payment-api

[1/7] Loading configuration
      Product: payment-api | Tier: critical
      CIA: C=high I=high A=moderate

[2/7] Running scanners + EPSS
      Findings: 22 | EPSS enriched: 13/16

[3/7] SP 800-30 Risk Assessment (static mode)
      Threat sources: 2 identified
      Threat events: 5 identified
      Risk determinations:
        VERY-HIGH: 1 (CVE-2023-50782 in cryptography)
        HIGH: 3
        MODERATE: 1

[4/7] Security Assessment Report (SAR)
      Controls assessed: 102
      Satisfied: 18
      Other-than-satisfied: 24
      Not assessed: 60
      Coverage: 41.2%

[5/7] Plan of Action & Milestones (POA&M)
      Items created: 8
        7-day deadline: 1 (VERY-HIGH)
        30-day deadline: 3 (HIGH)
        90-day deadline: 4 (MODERATE)

[6/7] Authorization Decision
      Decision: DATO (Denial of Authority to Operate)
      Reason: Gate BLOCKED + 1 VERY-HIGH risk finding
      Condition: Resolve POA&M items before re-assessment

[7/7] Reports exported
      output/sp800-30-payment-api.yaml
      output/sar-payment-api.yaml
      output/poam-payment-api.yaml
      output/authorization-payment-api.yaml

✓ RMF assessment complete.
```

### 5-3. ADR 추가

`docs/ADR.md`에 ADR-013 추가:

```
### ADR-013: Full NIST RMF Assessment with SP 800-30 + SAR + POA&M
**결정**: SP 800-30 4-phase risk assessment + SAR + POA&M + Authorization decision을 단일 `risk-assess` 명령으로 통합. AI (Bedrock Sonnet)는 Phase 2 (Conduct)에서 threat/vulnerability/likelihood/impact 분석을 수행하고, Phase 3 (Communicate)에서 보고서를 생성. SAR/POA&M/Authorization은 deterministic.
**이유**: RMF는 risk assessment만이 아니라 assessment 후 활동 (SAR, POA&M, ATO decision)까지 포함해야 완전한 프로세스. SP 800-30의 4-phase를 따르면 감사인이 방법론을 추적할 수 있음.
**트레이드오프**: Full SP 800-30 보고서는 길고 복잡함. 대부분의 개발자는 요약만 필요. executive_summary를 제공하되 전체 보고서도 export.
```

### 5-4. 테스트

`tests/unit/test_risk_assess_cli.py`:
- `test_risk_assess_help` — command help 출력
- `test_risk_assess_produces_4_reports` — 4개 YAML/JSON 파일 생성
- `test_risk_assess_static_mode` — Bedrock 없이 static 보고서 생성
- `test_risk_assess_authorization_dato` — gate BLOCK → DATO
- `test_risk_assess_authorization_ato` — gate PASS → ATO
- `test_risk_assess_poam_items_created` — POA&M 항목 생성

Scanner + Bedrock는 mock. 실제 CLI/API 미호출.

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint && python -m orchestrator risk-assess --help
```

## 금지사항

- AI 결과를 authorization 결정에 사용하지 마라. Authorization은 gate + POA&M 기반 (deterministic).
- 기존 `assess` command를 수정하지 마라. `risk-assess`는 별도 command.
- 실제 Bedrock API를 테스트에서 호출하지 마라.
