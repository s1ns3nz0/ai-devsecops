# Step 3: cli-integration

## 읽어야 할 파일

- `/orchestrator/cli.py` — 기존 assess, scan commands
- `/orchestrator/intelligence/epss.py` — EPSS client (Step 0)
- `/orchestrator/intelligence/enricher.py` — VulnerabilityEnricher (Step 1)
- `/orchestrator/intelligence/analyzer.py` — VulnAnalyzer (Step 2)
- `/orchestrator/evidence/jsonl.py` — JSONL writer
- `/orchestrator/scanners/grype.py` — Grype findings 소스
- `/orchestrator/config/manifest.py` — ProductManifest

## 작업

### 3-1. `vuln-intel` CLI Command

`orchestrator/cli.py`에 새 command 추가:

```python
@cli.command("vuln-intel")
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--top-n", default=5, help="Number of vulnerabilities for AI analysis")
@click.option("--output-jsonl", default=None)
def vuln_intel(target_path: str, product: str, top_n: int, output_jsonl: str | None) -> None:
    """Analyze vulnerabilities with EPSS enrichment and AI context.

    Runs Grype scan → enriches with EPSS scores → AI analyzes top-N.
    Engineers get exploit probability + attack scenario + fix priority.
    """
    ...
```

### 3-2. CLI Output Format

```
$ python -m orchestrator vuln-intel ./sample-app --product payment-api

[1/3] Scanning dependencies (Grype)
      Found: 16 vulnerabilities

[2/3] Enriching with EPSS exploit intelligence
      API: api.first.org/data/v1/epss
      Enriched: 14/16 CVEs (2 not in EPSS database)

[3/3] AI vulnerability analysis (top 5)
      Mode: static (no Bedrock configured)

╔══════════════════════════════════════════════════════════════════════╗
║ VULNERABILITY INTELLIGENCE REPORT: payment-api                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║ ① CVE-2023-50782 | cryptography 3.4.6                               ║
║   CVSS: HIGH (7.5) | EPSS: 0.672 (97th percentile)                 ║
║   Priority: CRITICAL — 67% chance of exploitation                    ║
║   Reachability: reachable (JWT signing in src/app.py:89)            ║
║   Attack: Bleichenbacher timing attack on RSA PKCS#1                ║
║   Impact: PCI-DSS-3.5.1 violated — cryptographic key exposure       ║
║   Fix: pip install cryptography>=41.0.6                              ║
║                                                                      ║
║ ② CVE-2022-29217 | PyJWT 1.7.1                                     ║
║   CVSS: HIGH (7.5) | EPSS: 0.234 (89th percentile)                 ║
║   Priority: HIGH — 23% chance of exploitation                        ║
║   Reachability: reachable (jwt.encode in src/app.py:92)             ║
║   Attack: Algorithm confusion — HS256 accepted instead of RS256     ║
║   Impact: ASVS-V3.5.3 violated — token forgery possible            ║
║   Fix: pip install PyJWT>=2.4.0                                      ║
║                                                                      ║
║ ③ CVE-2023-32681 | requests 2.25.0                                  ║
║   CVSS: MEDIUM (6.1) | EPSS: 0.012 (45th percentile)               ║
║   Priority: LOW — 1.2% chance of exploitation                        ║
║   Reachability: unknown                                              ║
║   Fix: pip install requests>=2.31.0                                  ║
║                                                                      ║
║ Summary: 16 total | 1 CRITICAL | 3 HIGH | 5 MEDIUM | 7 LOW         ║
║ Controls affected: PCI-DSS-3.5.1, PCI-DSS-6.3.1, ASVS-V3.5.3     ║
╚══════════════════════════════════════════════════════════════════════╝
```

### 3-3. Assess Command 통합

기존 `assess` command의 scanner 결과에 EPSS enrichment를 자동 추가:

```python
# After scanner findings are collected, enrich Grype findings with EPSS
grype_findings = [f for f in findings if f.source == "grype" and f.rule_id.startswith("CVE-")]
if grype_findings:
    enricher = VulnerabilityEnricher(EpssClient(), mapper)
    enriched = enricher.enrich(grype_findings, manifest)
    # Log enriched summary
    click.echo(f"      EPSS: {len(enriched)} CVEs enriched")
```

### 3-4. Evidence에 EPSS 포함

enriched vulnerability 정보를 JSONL에 기록하여 evidence chain에 포함:

```python
writer.write_entry({
    "type": "vuln_intelligence",
    "cve_id": vuln.cve_id,
    "epss_score": vuln.epss_score,
    "priority": vuln.priority,
    "analysis": analysis.reasoning if analysis else None,
})
```

### 3-5. ADR 추가

`docs/ADR.md`에 ADR-011 추가:

```
### ADR-011: EPSS + AI Vulnerability Intelligence
**결정**: CVSS severity 대신 EPSS exploit probability로 CVE 우선순위를 결정. 상위 N개 CVE는 AI가 attack scenario + reachability 분석.
**이유**: CVSS 7.5인 CVE가 1000개일 때, EPSS로 실제 exploit 가능성을 필터링하면 10개로 줄일 수 있음. AI는 코드 컨텍스트에서 도달 가능성을 분석하여 추가 필터링.
**트레이드오프**: EPSS API 의존성 (air-gapped 환경에서는 CVSS fallback). AI 분석은 Bedrock 필요 (static fallback 제공).
```

### 3-6. 테스트

`tests/unit/test_vuln_intel_cli.py`:
- `test_vuln_intel_help` — command help 출력
- `test_vuln_intel_enriches_findings` — EPSS enrichment 확인 (scanner + EPSS mock)
- `test_vuln_intel_sorts_by_epss` — EPSS 내림차순 정렬
- `test_vuln_intel_static_mode` — Bedrock 없을 때 static 분석
- `test_assess_includes_epss_summary` — assess에 EPSS enrichment 요약 포함

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint && python -m orchestrator vuln-intel --help
```

## 금지사항

- 실제 EPSS API나 Bedrock를 unit 테스트에서 호출하지 마라.
- AI 분석 결과를 gate 결정에 사용하지 마라 (ADR-004).
- 모든 CVE에 AI를 호출하지 마라. --top-n만 (default 5).
- 기존 assess 동작을 깨뜨리지 마라. EPSS enrichment는 추가 정보, 필수 아님.
