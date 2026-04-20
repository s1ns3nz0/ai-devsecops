"""MVP-0 E2E demo — wires existing modules into a single flow."""

from __future__ import annotations

import os
from pathlib import Path

import click
import yaml

from orchestrator.cli import get_assessor
from orchestrator.config.manifest import load_manifest
from orchestrator.config.profile import load_profile
from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.evidence.export import EvidenceExporter
from orchestrator.evidence.jsonl import JsonlWriter
from orchestrator.gate.threshold import ThresholdEvaluator
from orchestrator.scanners.control_mapper import ControlMapper
from orchestrator.scanners.runner import ScannerRunner
from orchestrator.sigma.engine import SigmaEngine

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_demo(target_path: str, product: str = "payment-api") -> None:
    """Run the full MVP-0 E2E demo.

    Flow:
    1. Load product manifest + risk profile, determine tier
    2. Select control baseline (RMF Step 3)
    3. Run all scanners (RMF Step 5)
    4. Gate evaluation (RMF Step 6)
    5. Risk assessment
    6. Sigma detection (log analysis)
    7. Evidence export
    """
    prod_dir = _PROJECT_ROOT / "controls" / "products" / product
    baselines_dir = str(_PROJECT_ROOT / "controls" / "baselines")
    tier_mappings = str(_PROJECT_ROOT / "controls" / "tier-mappings.yaml")
    output_dir = _PROJECT_ROOT / "output"
    jsonl_path = str(output_dir / "findings.jsonl")
    evidence_dir = str(output_dir / "evidence")
    log_path = Path(target_path) / "logs" / "access.jsonl"
    sigma_rules_dir = str(_PROJECT_ROOT / "sigma" / "rules")

    # ── [1/7] Load product manifest ─────────────────────────────
    click.echo(f"[1/7] Loading product manifest: {product}")
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))
    profile = load_profile(str(prod_dir / "risk-profile.yaml"))

    repo = ControlsRepository(baselines_dir=baselines_dir, tier_mappings_path=tier_mappings)
    repo.load_all()

    assessor = get_assessor(repo)
    tier = assessor.categorize(manifest)

    data_classes = ", ".join(manifest.data_classification)
    click.echo(f"      Product: {product} | Data: {data_classes} | Tier: {tier.value}")

    # ── [2/7] Select control baseline ───────────────────────────
    click.echo("\n[2/7] Selecting control baseline (RMF Step 3: Select)")
    controls = select_baseline(repo, manifest, tier)

    fw_counts: dict[str, int] = {}
    for c in controls:
        fw_counts[c.framework] = fw_counts.get(c.framework, 0) + 1
    fw_detail = ", ".join(f"{fw} ({n})" for fw, n in sorted(fw_counts.items()))
    click.echo(f"      Frameworks applied: {fw_detail}")
    click.echo(f"      Total controls: {len(controls)}")

    # ── [3/7] Run scanners ──────────────────────────────────────
    click.echo("\n[3/7] Running scanners (RMF Step 5: Assess)")
    mapper = ControlMapper(repo)
    from orchestrator.cli import _build_scanners

    scanners = _build_scanners(mapper)
    runner = ScannerRunner(scanners)
    findings = runner.run_all(target_path)

    for f in findings:
        f.product = product

    scanner_counts: dict[str, int] = {}
    for f in findings:
        scanner_counts[f.source] = scanner_counts.get(f.source, 0) + 1

    for src in ["checkov", "semgrep", "grype", "gitleaks"]:
        count = scanner_counts.get(src, 0)
        click.echo(f"      {src.capitalize()}: {count} findings")

    # Write findings to JSONL
    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    # ── [4/7] Gate evaluation ───────────────────────────────────
    click.echo("\n[4/7] Gate evaluation (RMF Step 6: Authorize)")
    evaluator = ThresholdEvaluator(profile)
    gate = evaluator.evaluate(findings, tier)
    writer.write_gate_decision(gate, product)

    if gate.passed:
        click.echo("      PASSED — all checks within thresholds")
    else:
        click.echo(f"      {gate.reason}")

    # ── [5/7] Risk assessment ───────────────────────────────────
    click.echo("\n[5/7] Risk assessment")
    report = assessor.assess(findings, manifest, controls, "pre_merge")
    writer.write_risk_report(report)

    mode = "AI-augmented" if os.environ.get("BEDROCK_MODEL_ID") else "static"
    click.echo(f"      Risk score: {report.risk_score:.1f}/10")
    click.echo(f"      Mode: {mode}")

    # Save risk assessment YAML
    ra_dir = prod_dir / "risk-assessments"
    ra_dir.mkdir(parents=True, exist_ok=True)
    ra_data = {
        "id": report.id,
        "trigger": report.trigger,
        "product": report.product,
        "risk_tier": report.risk_tier.value,
        "risk_score": report.risk_score,
        "narrative": report.narrative,
        "gate_recommendation": report.gate_recommendation,
    }
    (ra_dir / f"{report.id}.yaml").write_text(yaml.dump(ra_data, default_flow_style=False))

    # ── [6/7] Detection analysis ────────────────────────────────
    click.echo("\n[6/7] Detection analysis")
    sigma_matches = []
    if log_path.exists():
        engine = SigmaEngine(sigma_rules_dir)
        engine.load_rules()
        sigma_matches = engine.evaluate_log_file(str(log_path))

        if sigma_matches:
            sigma_findings = [m.to_finding(product=product) for m in sigma_matches]
            writer.write_findings(sigma_findings)

        click.echo(f"      Sigma rules: {len(sigma_matches)} matches")
        tags = sorted({t for m in sigma_matches for t in m.rule.tags})
        if tags:
            click.echo(f"      ATT&CK coverage: {', '.join(t.replace('attack.', '').upper() for t in tags)}")
    else:
        click.echo("      No log file found, skipping detection")

    # ── [7/7] Evidence export ───────────────────────────────────
    click.echo("\n[7/7] Evidence export")
    exporter = EvidenceExporter(jsonl_reader=writer, controls_repo=repo)
    evidence = exporter.export(product=product, output_path=evidence_dir)

    report_file = Path(evidence_dir) / f"{evidence['report_id']}.json"
    summary = evidence["summary"]
    click.echo(f"      Report: {report_file}")
    click.echo(f"      Controls coverage: {summary['coverage_percentage']}%")

    click.echo(f"\n\u2713 Demo complete. See {output_dir}/ for full results.")
