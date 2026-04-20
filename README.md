# Compliance-Driven AI Risk Platform

[![CI](https://github.com/s1ns3nz0/ai-devsecops/actions/workflows/ci.yml/badge.svg)](https://github.com/s1ns3nz0/ai-devsecops/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**A DevSecOps platform that treats compliance frameworks as the single source of truth.**

Instead of aggregating scanner output and mapping to compliance as an afterthought, this platform starts from the compliance framework and derives verification activities from applicable controls. AI translates context between layers without making gate decisions.

> Risk drives controls. Controls drive verification. Verification produces evidence.
> AI translates context between each layer — without making final decisions.

```
Compliance Framework (PCI DSS, ASVS, FISC)
       |  Controls selected by risk tier
       v
DevSecOps Pipeline (Plan > Develop > Build > Test > Deploy > Monitor)
       |  Scanners configured per control
       v
Findings tagged with Control IDs
       |  Deterministic gate (YAML thresholds)
       v
Audit-Ready Evidence (single query by Control ID)
```

## Why This Exists

Current ASPM tools (Cycode, ArmorCode, Snyk AppRisk, etc.) share a pattern: ingest findings, correlate, report. Compliance mapping is downstream.

This platform inverts that:

| | Existing ASPM | This Platform |
|---|---|---|
| Starting point | Scanner output | Compliance framework |
| Control mapping | Downstream report | Upstream driver |
| AI role | Triage & prioritization | Context translation (never gating) |
| Gate decisions | Mixed (AI-influenced) | Strictly deterministic (YAML + OPA) |
| Evidence chain | Dashboard aggregate | Single Control ID traceability |

## Quick Start

```bash
git clone https://github.com/s1ns3nz0/ai-devsecops.git
cd ai-devsecops
make setup
make demo          # fixture-based demo (no external tools needed)
```

With scanners installed (checkov, semgrep, grype, gitleaks):

```bash
make demo          # real scanner findings against sample vulnerable app
```

With AWS Bedrock configured:

```bash
make demo-full     # AI-augmented risk assessment narratives
```

## Demo Output

> Replay the demo locally: `asciinema play assets/demo.cast`

```
[1/7] Loading product manifest: payment-api
      Product: payment-api | Data: PCI, PII-financial | Tier: critical

[2/7] Selecting control baseline (RMF Step 3: Select)
      Frameworks applied: PCI-DSS-4.0 (5), ASVS-5.0-L3 (4), FISC (3)
      Total controls: 12

[3/7] Running scanners (RMF Step 5: Assess)
      Checkov:  20 findings (IaC misconfigurations)
      Semgrep:   0 findings
      Grype:    20 findings (dependency CVEs)
      Gitleaks:  1 finding  (hardcoded AWS key)

[4/7] Gate evaluation (RMF Step 6: Authorize)
      BLOCKED: max_critical_findings violated (found 1, limit 0)
      BLOCKED: max_secrets_detected violated (found 1, limit 0)

[5/7] Risk assessment
      Risk score: 9.0/10
      Mode: static (deterministic scoring)

[6/7] Detection analysis
      Sigma rules: 5 matches (brute force, SQLi, exfiltration)
      ATT&CK coverage: T1110, T1190, T1048

[7/7] Evidence export
      Controls coverage: 75.0%
      Report: output/evidence/EVD-2026-0420-001.json
```

## Architecture

```
+---------------------------------------------------------+
|  Cross-cutting: Compliance Control Plane                 |
|  Controls Repository (OSCAL YAML) + Risk Assessment      |
|  Control ID traces through every phase                    |
+---------------------------------------------------------+
      |             |              |              |
  +--------+  +----------+  +----------+  +-----------+
  |  Plan  |->| Develop  |->|  Build   |->|   Test    |
  | Risk   |  | Semgrep  |  | Grype    |  | Gate      |
  | Assess |  | Gitleaks |  | SBOM     |  | Decision  |
  | Select |  | Checkov  |  |          |  |           |
  +--------+  +----------+  +----------+  +-----------+
      |             |              |              |
  +--------+  +--------------------------------------+
  | Operate|  |            Monitor                    |
  |        |  | Sigma Engine - ATT&CK - Re-assessment |
  +--------+  +--------------------------------------+
```

### Key Design Decisions

- **NIST RMF** as internal methodology — users configure frameworks, platform handles the lifecycle
- **Gate path is 100% local** — no network dependency for pass/fail decisions
- **AI never gates** — YAML thresholds + OPA make blocking decisions; AI provides narrative and recommendations
- **Works without AI** — `StaticRiskAssessor` runs deterministic scoring; `BedrockRiskAssessor` adds cross-signal reasoning when AWS Bedrock is configured
- **Control ID as primary key** — single identifier links framework requirement to scanner finding to evidence artifact

## Components

| Component | What it does | Lines |
|---|---|---|
| **Controls Repository** | 12 OSCAL YAML controls (PCI-DSS, ASVS, FISC) with tier-based baseline selection | ~280 |
| **Scanner Integration** | Checkov (IaC), Semgrep (SAST), Grype (SCA), Gitleaks (secrets) with Control ID mapping | ~500 |
| **Gate Engine** | YAML threshold evaluator — deterministic, no AI, 100% local | ~120 |
| **Risk Assessment** | StaticRiskAssessor + BedrockRiskAssessor (Strategy pattern) | ~400 |
| **Evidence Export** | JSONL append-only writer + JSON evidence report generator | ~260 |
| **Sigma Engine** | Custom Python Sigma matcher (144 LOC), 4 detection rules with ATT&CK tags | ~190 |
| **CLI** | `init`, `scan`, `assess`, `detect`, `export`, `demo` | ~370 |

## Compliance Frameworks

| Framework | Controls | Scope |
|---|---|---|
| PCI DSS 4.0 | 5 controls (Sec 1, 3, 6, 10) | Payment card data protection |
| OWASP ASVS 5.0 L3 | 4 controls (V2, V3, V5, V14) | Application security verification |
| FISC Safety Standard | 3 controls | Japanese financial industry security |

Controls are auto-selected by risk tier:

| Tier | Frameworks Applied | Trigger |
|---|---|---|
| LOW | None | No sensitive data |
| MEDIUM | ASVS | PII or moderate sensitivity |
| HIGH | PCI-DSS + ASVS | Payment/financial data |
| CRITICAL | PCI-DSS + ASVS + FISC | Regulated financial + Japan |

## AI Strategy

The AI layer (AWS Bedrock, Claude Sonnet 4.6) adds value through **cross-signal reasoning** — connecting findings across scanners, code changes, and compliance context:

1. **Contextual blast radius** — "This S3 bucket is in the same VPC as the payment DB, combined with the permissive IAM policy..."
2. **VEX exploitability** — "This CVE affects lodash.merge but the codebase only uses lodash.get — code not reachable"
3. **Semantic security review** — "JWT validation changed from RS256 to HS256 — cryptographic downgrade violating ASVS-V3.5.1"

AI never makes the block/allow decision. That's deterministic. AI explains *why* the decision matters.

```
WITHOUT AI                           WITH AI
-----------                          --------
User fills form manually      -->    One-sentence product description
Deterministic risk score       -->    + AI cross-signal narrative
Raw JSON evidence              -->    + Auditor-facing prose
Manual gap analysis            -->    + AI identifies missing controls
```

## Evidence Report Sample

Query: *"Show evidence for ASVS-V2.10.1 (No hardcoded credentials)"*

```json
{
  "control_id": "ASVS-V2.10.1",
  "title": "No hardcoded credentials in source code",
  "framework": "asvs-5.0-L3",
  "status": "partial",
  "evidence": {
    "findings": [{
      "source": "gitleaks",
      "rule_id": "generic-api-key",
      "severity": "critical",
      "message": "Detected a Generic API Key",
      "control_ids": ["ASVS-V2.10.1", "PCI-DSS-3.5.1"]
    }],
    "scanners_used": ["gitleaks"]
  }
}
```

One Control ID traces from framework requirement to scanner finding to evidence artifact.

## Testing

```bash
make test            # 124 unit tests (<1s)
make test-contract   # contract tests (recorded API responses)
make lint            # ruff + mypy strict mode
```

## Documentation

- [Architecture Design](docs/architecture-design.md) — full design document: positioning, risk methodology, AI strategy, gating, E2E scenario
- [Architecture](docs/ARCHITECTURE.md) — system design, data flow, directory structure
- [ADR](docs/ADR.md) — 8 architecture decision records with rationale
- [PRD](docs/PRD.md) — product requirements and MVP scope

## Target Roles

This platform demonstrates competencies for:

- **Security Engineer (Binance)** — internal security platform built from scratch in Python, CI/CD automation, detection engineering
- **Cloud Platform Engineer (PayPay)** — Terraform IaC policy gate, PCI DSS baseline, AI/ML via Bedrock
- **Product Security (Money Forward)** — NIST CSF/CIS Controls, FISC mapping, architecture review, DevSecOps tooling

## License

MIT
