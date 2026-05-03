# Step 2: cli-import

## 읽어야 할 파일

- `/orchestrator/cli.py` — 기존 commands
- `/orchestrator/importer/oscal.py` — OscalParser, GenericFrameworkParser, BaselineGenerator (Step 0)
- `/orchestrator/importer/suggest.py` — ScannerSuggester (Step 1)
- `/controls/compliance-mappings.yaml` — framework 등록 위치
- `/controls/tier-mappings.yaml` — tier 매핑 위치
- `/docs/ADR.md`

## 작업

### 2-1. `import-framework` CLI Command

```python
@cli.command("import-framework")
@click.argument("source")
@click.option("--framework-id", required=True, help="Framework identifier (e.g., cmmc-2.0-L2)")
@click.option("--format", "fmt", default="oscal", type=click.Choice(["oscal", "asvs-json", "generic-json"]))
@click.option("--output", default=None, help="Output YAML path (default: controls/baselines/{framework-id}.yaml)")
@click.option("--suggest-scanners", is_flag=True, default=True, help="Auto-suggest scanner mappings via keyword matching")
@click.option("--tiers", default="high,critical", help="Applicable tiers (comma-separated)")
def import_framework(
    source: str,
    framework_id: str,
    fmt: str,
    output: str | None,
    suggest_scanners: bool,
    tiers: str,
) -> None:
    """Import a compliance framework and generate baseline YAML.

    SOURCE can be a local file path or a URL.

    Examples:
      # Import NIST 800-53 from OSCAL JSON
      orchestrator import-framework ./nist-800-53-catalog.json --framework-id nist-800-53-r5

      # Import from URL
      orchestrator import-framework https://raw.githubusercontent.com/usnistgov/oscal-content/main/... --framework-id nist-800-53-r5

      # Import OWASP ASVS
      orchestrator import-framework ./asvs-4.0.3.json --framework-id asvs-4.0.3-L2 --format asvs-json

      # Without scanner suggestions
      orchestrator import-framework ./cmmc.json --framework-id cmmc-2.0-L2 --suggest-scanners=false

    Flow:
    1. Parse source (OSCAL JSON / ASVS JSON / generic)
    2. Generate baseline YAML with empty verification_methods
    3. If --suggest-scanners: apply keyword-based scanner suggestions
    4. Print summary (imported count, suggested count, unmapped count)
    5. Remind user to review and approve scanner mappings
    """
    ...
```

### 2-2. CLI Output

```
$ python -m orchestrator import-framework ./nist-800-171.json \
    --framework-id cmmc-2.0-L2 --tiers high,critical

[1/3] Parsing OSCAL catalog
      Source: ./nist-800-171.json
      Format: oscal
      Controls found: 110

[2/3] Generating baseline YAML
      Output: controls/baselines/cmmc-2.0-L2.yaml
      Applicable tiers: high, critical

[3/3] Suggesting scanner mappings
      Suggested: 78/110 controls (keyword match)
      Unmapped: 32/110 controls (manual review needed)

      Suggested mappings:
        checkov:  45 controls (IAM, network, encryption checks)
        semgrep:  38 controls (code security, auth, crypto)
        gitleaks: 12 controls (credential management)
        grype:     8 controls (vulnerability management)
        sigma:    15 controls (monitoring, detection)
        sbom:      5 controls (software inventory)

✓ Baseline generated: controls/baselines/cmmc-2.0-L2.yaml

⚠ IMPORTANT: Scanner mappings are SUGGESTIONS based on keyword matching.
  A security engineer must review and approve each mapping before use.
  32 controls have no suggested mapping and need manual assignment.

Next steps:
  1. Review controls/baselines/cmmc-2.0-L2.yaml
  2. Verify scanner mappings are correct
  3. Add framework to controls/compliance-mappings.yaml:
       data_classifications:
         CUI:
           frameworks: [cmmc-2.0-L2]
  4. Add framework to controls/tier-mappings.yaml
  5. Run: orchestrator assess ./your-app --product your-product
```

### 2-3. ADR 추가

`docs/ADR.md`에 ADR-012 추가:

```
### ADR-012: Framework Import from OSCAL + Keyword-Based Scanner Suggestion
**결정**: NIST OSCAL JSON catalog에서 컨트롤을 자동 import하고, 키워드 매칭으로 scanner mapping을 제안. 제안은 인간이 반드시 검토 후 승인.
**이유**: 새 프레임워크 추가 시 110+ 컨트롤을 수동으로 YAML에 작성하는 것은 비현실적. OSCAL import + keyword suggestion으로 초기 작업의 70%를 자동화하면서, 정확성은 인간 검토로 보장.
**트레이드오프**: 키워드 매칭은 30% 정도의 컨트롤에 대해 제안을 못함 (물리적 보안, 인적 절차 등 자동화 불가 영역). 이런 컨트롤은 verification_methods: []로 남겨져 수동 매핑 또는 "not-automatable" 표시 필요.
```

### 2-4. 테스트

`tests/unit/test_import_cli.py`:
- `test_import_framework_help` — command help 출력
- `test_import_oscal_creates_yaml` — OSCAL fixture → YAML 파일 생성
- `test_import_with_suggestions` — YAML에 제안된 verification_methods 포함
- `test_import_without_suggestions` — --suggest-scanners=false → verification_methods: []
- `test_import_prints_summary` — 출력에 imported/suggested/unmapped 카운트 포함
- `test_import_from_url` — URL mock → 파싱 성공

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint && python -m orchestrator import-framework --help
```

## 금지사항

- AI/Bedrock를 사용하지 마라. 키워드 매칭만.
- 기존 baselines/*.yaml을 수정하지 마라. 새 파일만 생성.
- compliance-mappings.yaml이나 tier-mappings.yaml을 자동 수정하지 마라. 사용자에게 다음 단계를 안내만.
- 제안을 "확정"으로 표시하지 마라. 항상 "suggested — review required" 라벨.
