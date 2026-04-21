# CloudGoat Scan Results

Real scan results from running the platform against [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) — Rhino Security Labs' vulnerable-by-design AWS deployment tool.

## Scan Summary

| Metric | Value |
|---|---|
| **Target** | CloudGoat (AWS IaC + Python + Node.js) |
| **Product tier** | HIGH (PCI + PII-financial) |
| **Frameworks applied** | PCI-DSS 4.0, ASVS 5.0 L3 |

### Scanner Results

| Scanner | Findings | Severity Breakdown |
|---|---|---|
| Semgrep (SAST) | 318 | 111 high, 192 medium, 15 low |
| Gitleaks (secrets) | 17 | 17 critical (hardcoded credentials) |
| Grype (SCA) | 12 | 7 high, 4 medium, 1 low |
| Sigma (detection) | 9 | 8 high, 1 critical |
| SBOM (supply chain) | 1 | 1 info |
| **Total** | **357** | |

### SBOM

| Metric | Value |
|---|---|
| Format | CycloneDX 1.6 |
| Components | 132 (51 Python, 1 Go, 80 other) |

### Gate Decision

```
BLOCKED:
  - max_critical_findings violated — found 17, limit 0 (control: ASVS-V2.10.1)
  - max_high_findings_pci violated — found 14, limit 0 (control: PCI-DSS-6.3.1)
```

### Risk Score

**8.5/10** (static mode)

### Sigma Detection

9 attack patterns detected (brute force ×5, SQLi ×2, exfiltration ×1, privilege escalation ×1)

### Evidence Coverage

**69.2%** (7 full, 2 partial, 4 none)

| Control | Status | Findings | Scanners |
|---|---|---|---|
| ASVS-V2.10.1 (credentials) | partial | 17 | gitleaks |
| ASVS-V5.3.4 (SQLi) | full | 53 | semgrep |
| ASVS-V14.2.1 (dependencies) | full | 7 | grype |
| PCI-DSS-3.5.1 (keys) | full | 17 | gitleaks |
| PCI-DSS-6.3.1 (vulnerabilities) | full | 69 | semgrep, grype |
| PCI-DSS-6.3.2 (SBOM) | full | 8 | grype, sbom |
| PCI-DSS-10.2.1 (audit logs) | full | 6 | sigma |
| FISC-実127 (monitoring) | full | 5 | sigma |

## Files

- `evidence-report.json` — full evidence report with control-by-control findings
- `sbom.cdx.json` — CycloneDX SBOM (132 components)

## How to reproduce

```bash
git clone --depth 1 https://github.com/RhinoSecurityLabs/cloudgoat.git /tmp/cloudgoat
python -m orchestrator assess /tmp/cloudgoat --product cloudgoat --trigger pre_merge
python -m orchestrator sbom /tmp/cloudgoat --output-dir output
python -m orchestrator export --product cloudgoat
```
