"""CLI entry point — thin wiring layer over existing modules."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import yaml

from orchestrator.assessor.interface import RiskAssessor
from orchestrator.assessor.static import StaticRiskAssessor
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
from orchestrator.types import Finding, RiskTier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _default_path(relative: str) -> str:
    return str(_PROJECT_ROOT / relative)


def get_assessor(controls_repo: ControlsRepository) -> RiskAssessor:
    """Return an appropriate RiskAssessor based on environment.

    - BEDROCK_MODEL_ID set + boto3 importable → BedrockRiskAssessor
    - Otherwise → StaticRiskAssessor
    """
    model_id = os.environ.get("BEDROCK_MODEL_ID")
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")
    if model_id:
        try:
            from orchestrator.assessor.bedrock import BedrockRiskAssessor
            from orchestrator.assessor.bedrock_client import BedrockClient

            client = BedrockClient(model_id=model_id, region=region)
            return BedrockRiskAssessor(client=client)
        except Exception:
            pass
    return StaticRiskAssessor()


@click.group()
def cli() -> None:
    """Compliance-Driven AI Risk Platform"""


@cli.command()
@click.option("--output-dir", default=None, help="Base directory for product configs")
def init(output_dir: str | None) -> None:
    """Create product-manifest.yaml and risk-profile.yaml interactively."""
    base = Path(output_dir) if output_dir else _PROJECT_ROOT / "controls" / "products"

    name = click.prompt("Product name")
    description = click.prompt("Description")
    data_class = click.prompt("Data classification (comma-separated, e.g. PCI,PII-financial)")
    jurisdiction = click.prompt("Jurisdiction (comma-separated, e.g. JP,US)")
    cloud = click.prompt("Cloud provider")
    compute = click.prompt("Compute type")
    region = click.prompt("Region")

    data_classifications = [c.strip() for c in data_class.split(",")]
    jurisdictions = [j.strip() for j in jurisdiction.split(",")]

    product_dir = base / name
    product_dir.mkdir(parents=True, exist_ok=True)
    (product_dir / "risk-assessments").mkdir(exist_ok=True)

    manifest = {
        "product": {
            "name": name,
            "description": description,
            "data_classification": data_classifications,
            "jurisdiction": jurisdictions,
            "deployment": {"cloud": cloud, "compute": compute, "region": region},
            "integrations": [],
        }
    }
    manifest_path = product_dir / "product-manifest.yaml"
    manifest_path.write_text(yaml.dump(manifest, default_flow_style=False))

    # Determine risk tier
    from orchestrator.config.manifest import load_manifest as _load

    loaded = _load(str(manifest_path))
    assessor = StaticRiskAssessor()
    tier = assessor.categorize(loaded)

    # Generate risk profile based on tier
    if tier in (RiskTier.CRITICAL, RiskTier.HIGH):
        action = "block"
    else:
        action = "proceed"

    profile = {
        "risk_profile": {
            "frameworks": ["pci-dss-4.0"] if "PCI" in data_class.upper() else ["asvs-4.0.3-L3"],
            "risk_appetite": "conservative" if tier in (RiskTier.CRITICAL, RiskTier.HIGH) else "moderate",
            "thresholds": {
                "critical": {"max_critical_findings": 0, "max_secrets_detected": 0, "action": action},
                "high": {"max_critical_findings": 0, "action": action},
                "medium": {"max_high_findings": 5, "action": "proceed"},
                "low": {"action": "proceed"},
            },
            "failure_policy": {
                "critical": {"scan_failure": "block"},
                "high": {"scan_failure": "block"},
                "medium": {"scan_failure": "proceed"},
                "low": {"scan_failure": "proceed"},
            },
        }
    }
    (product_dir / "risk-profile.yaml").write_text(yaml.dump(profile, default_flow_style=False))

    click.echo(f"Product: {name} | Tier: {tier.value}")
    click.echo(f"Created: {manifest_path}")
    click.echo(f"Created: {product_dir / 'risk-profile.yaml'}")


@cli.command()
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
@click.option("--controls-dir", default=None, help="Controls baselines directory")
@click.option("--tier-mappings", default=None, help="Path to tier-mappings.yaml")
@click.option("--output-jsonl", default=None, help="JSONL output path")
def scan(
    target_path: str,
    product: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    output_jsonl: str | None,
) -> None:
    """Scan target_path and record findings to JSONL."""
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    mapper = ControlMapper(repo)
    scanners = _build_scanners(mapper)
    runner = ScannerRunner(scanners)
    findings = runner.run_all(target_path)

    # Tag findings with product name
    for f in findings:
        f.product = product

    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    click.echo(f"[scan] {len(findings)} findings recorded to {jsonl_path}")


@cli.command()
@click.argument("target_path")
@click.option("--product", required=True, help="Product name")
@click.option("--trigger", default="pre_merge", type=click.Choice(["pre_merge", "pre_deploy", "periodic"]))
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
@click.option("--product-dir", default=None)
@click.option("--output-jsonl", default=None)
@click.option("--retry", is_flag=True, default=False, help="Enable retry with failure policy")
@click.option("--force-override", is_flag=True, default=False, help="Override a scan failure block")
@click.option("--override-reason", default=None, help="Predefined override reason category")
@click.option("--override-justification", default=None, help="Free text explanation for override")
def assess(
    target_path: str,
    product: str,
    trigger: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    product_dir: str | None,
    output_jsonl: str | None,
    retry: bool,
    force_override: bool,
    override_reason: str | None,
    override_justification: str | None,
) -> None:
    """Run full risk assessment: scan + gate + risk report.

    Exit code 0 = gate passed, 1 = gate blocked.
    """
    prod_dir = Path(product_dir) if product_dir else _PROJECT_ROOT / "controls" / "products" / product
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    # [1/4] Load configuration
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))
    profile = load_profile(str(prod_dir / "risk-profile.yaml"))

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    assessor = get_assessor(repo)
    tier = assessor.categorize(manifest)
    controls = select_baseline(repo, manifest, tier)
    frameworks = ", ".join(profile.frameworks)

    click.echo("[1/4] Loading configuration")
    click.echo(f"      Product: {product} | Tier: {tier.value} | Frameworks: {frameworks}")

    # [2/4] Run scanners
    click.echo("[2/4] Running scanners")
    mapper = ControlMapper(repo)
    scanners = _build_scanners(mapper)

    retry_results = None
    if retry:
        from orchestrator.resilience.retry import RetryConfig

        runner_obj = ScannerRunner(scanners, retry_config=RetryConfig())
        findings, retry_results = runner_obj.run_all_with_retry(target_path)
    else:
        runner_obj = ScannerRunner(scanners)
        findings = runner_obj.run_all(target_path)

    for f in findings:
        f.product = product

    # Summarize per scanner
    scanner_counts: dict[str, dict[str, int]] = {}
    for f in findings:
        sc = scanner_counts.setdefault(f.source, {})
        sc[f.severity] = sc.get(f.severity, 0) + 1

    for src, sevs in scanner_counts.items():
        total = sum(sevs.values())
        detail = ", ".join(f"{v} {k}" for k, v in sorted(sevs.items()))
        click.echo(f"      {src}: {total} findings ({detail})")

    if not findings:
        click.echo("      No findings")

    # [2.5/4] Failure policy evaluation (only when retry is enabled)
    if retry and retry_results is not None:
        from orchestrator.resilience.failure import FailureHandler
        from orchestrator.resilience.override import OverrideManager

        handler = FailureHandler(profile)
        decision = handler.handle(retry_results, tier)

        failed = decision.failed_scanners
        if failed:
            click.echo("[2.5/4] Failure policy evaluation")
            click.echo(f"      Failed scanners: {', '.join(failed)}")
            click.echo(f"      Tier: {tier.value} \u2192 policy: {decision.action}")

            if decision.action == "block":
                if force_override:
                    if not override_reason:
                        click.echo("      Error: --force-override requires --override-reason")
                        sys.exit(1)

                    writer = JsonlWriter(jsonl_path)
                    mgr = OverrideManager(writer)
                    record = mgr.create_override(
                        product=product,
                        tier=tier.value,
                        failed_scanners=failed,
                        reason=override_reason,
                        justification=override_justification or "",
                        approver="force-override",
                    )
                    click.echo("      Action: OVERRIDE GRANTED")
                    click.echo(f"      Reason: {record.reason}")
                    click.echo(f"      Justification: \"{record.justification}\"")
                    click.echo(f"      SLA deadline: {record.deferred_scan_sla}")
                    click.echo(f"      Override recorded: {record.id}")
                else:
                    click.echo(f"      Action: BLOCKED \u2014 scanner failure in {tier.value} tier")
                    click.echo("      Override: use --force-override --override-reason <reason>")
                    sys.exit(1)
            else:
                # warn_and_proceed
                click.echo(f"      Action: {decision.action} \u2014 {decision.reason}")

    # SBOM generation (supply chain evidence)
    try:
        from orchestrator.scanners.sbom import SbomGenerator

        sbom_gen = SbomGenerator()
        sbom_result = sbom_gen.generate(target_path, str(_PROJECT_ROOT / "output"))
        sbom_control_ids = mapper.map_finding("sbom", "sbom-generated")
        # Ensure control_ids is a real list (not a mock)
        if not isinstance(sbom_control_ids, list):
            sbom_control_ids = []
        findings.append(
            Finding(
                source="sbom",
                rule_id="sbom-generated",
                severity="info",
                file=sbom_result.sbom_path,
                line=0,
                message=f"CycloneDX SBOM generated: {sbom_result.components_count} components",
                control_ids=sbom_control_ids,
                product=product,
            )
        )
    except Exception:
        pass  # SBOM generation is optional (syft may not be installed)

    # Write findings to JSONL
    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    # Evidence path: optionally sync to DefectDojo (after JSONL, before gate)
    try:
        from orchestrator.integrations.defectdojo import DefectDojoClient

        dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
        dd_key = os.environ.get("DD_API_KEY", "")
        if dd_key:
            dd = DefectDojoClient(base_url=dd_url, api_key=dd_key)
            if dd.health_check():
                product_id = dd.get_or_create_product(product)
                engagement_id = dd.get_or_create_engagement(product_id, f"assess-{trigger}")
                dd.import_findings(engagement_id, findings)
                click.echo(f"      DefectDojo: {len(findings)} findings synced")
    except Exception:
        pass  # DefectDojo is optional (evidence path only)

    # [3/4] Gate evaluation — two additive layers (YAML + OPA)
    from orchestrator.gate.combined import CombinedGateEvaluator
    from orchestrator.gate.opa import OpaEvaluator

    threshold_eval = ThresholdEvaluator(profile)
    opa_eval = OpaEvaluator(str(_PROJECT_ROOT / "rego" / "gates"))
    combined = CombinedGateEvaluator(threshold_eval, opa_eval)

    context: dict[str, object] = {
        "product": product,
        "tier": tier.value,
        "frameworks": profile.frameworks,
        "findings_count": {
            s: sum(1 for f in findings if f.severity == s)
            for s in ["critical", "high", "medium", "low"]
        },
        "pci_scope_count": sum(
            1 for f in findings if any(c.startswith("PCI-DSS") for c in f.control_ids)
        ),
        "secrets_count": sum(1 for f in findings if f.source == "gitleaks"),
    }
    gate = combined.evaluate(findings, tier, context)

    click.echo("[3/4] Gate evaluation")
    if gate.passed:
        click.echo(f"      {gate.reason}")
    else:
        click.echo(f"      {gate.reason}")

    writer.write_gate_decision(gate, product)

    # [4/4] Risk assessment
    report = assessor.assess(findings, manifest, controls, trigger)
    writer.write_risk_report(report)

    mode = "bedrock" if os.environ.get("BEDROCK_MODEL_ID") else "static"
    click.echo("[4/4] Risk assessment")
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
    click.echo(f"\nReport saved: {ra_dir / f'{report.id}.yaml'}")
    click.echo(f"Findings logged: {jsonl_path} ({len(findings)} entries)")

    if not gate.passed:
        sys.exit(1)


@cli.command(name="export")
@click.option("--product", required=True)
@click.option("--control-id", default=None)
@click.option("--period", default=None)
@click.option("--output", default="output/evidence")
@click.option("--jsonl-path", default=None)
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
def export_cmd(
    product: str,
    control_id: str | None,
    period: str | None,
    output: str,
    jsonl_path: str | None,
    controls_dir: str | None,
    tier_mappings: str | None,
) -> None:
    """Generate evidence report as JSON."""
    jpath = jsonl_path or _default_path("output/findings.jsonl")
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")

    reader = JsonlWriter(jpath)
    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    # Optionally use DefectDojo as data source
    dd_client = None
    try:
        dd_key = os.environ.get("DD_API_KEY", "")
        if dd_key:
            from orchestrator.integrations.defectdojo import DefectDojoClient

            dd_url = os.environ.get("DEFECTDOJO_URL", "http://127.0.0.1:8080")
            dd_client = DefectDojoClient(base_url=dd_url, api_key=dd_key)
    except Exception:
        pass

    exporter = EvidenceExporter(jsonl_reader=reader, controls_repo=repo, defectdojo_client=dd_client)
    report = exporter.export(product=product, control_id=control_id, period=period, output_path=output)

    click.echo(f"Evidence report: {output}/{report['report_id']}.json")
    summary = report["summary"]
    click.echo(
        f"Coverage: {summary['coverage_percentage']}% "
        f"({summary['fully_evidenced']} full, "
        f"{summary['partially_evidenced']} partial, "
        f"{summary['no_evidence']} none)"
    )

    # Executive summary: findings by control
    exec_summary = report.get("executive_summary", {})
    if exec_summary:
        click.echo(f"\nFindings: {exec_summary['total_findings']} total, "
                    f"{exec_summary['mapped_to_controls']} mapped to controls, "
                    f"{exec_summary['unmapped_findings']} unmapped")
        click.echo("\nControl evidence:")
        for cs in exec_summary.get("controls", []):
            icon = {"full": "[OK]", "partial": "[!!]", "none": "[  ]"}.get(cs["status"], "[??]")
            sev = ", ".join(f"{v} {k}" for k, v in cs["severity_distribution"].items()) if cs["severity_distribution"] else "—"
            click.echo(f"  {icon} {cs['control_id']:<20} {cs['findings_count']:>4} findings  ({sev})")


@cli.command()
@click.argument("log_path")
@click.option("--product", default="")
@click.option("--rules-dir", default=None)
@click.option("--output-jsonl", default=None)
def detect(log_path: str, product: str, rules_dir: str | None, output_jsonl: str | None) -> None:
    """Analyze log file with Sigma rules."""
    rdir = rules_dir or _default_path("sigma/rules")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    engine = SigmaEngine(rdir)
    engine.load_rules()

    matches = engine.evaluate_log_file(log_path)

    if matches:
        writer = JsonlWriter(jsonl_path)
        findings = [m.to_finding(product=product) for m in matches]
        writer.write_findings(findings)

        for m in matches:
            tags = ", ".join(m.rule.tags) if m.rule.tags else "none"
            cids = ", ".join(m.rule.control_ids) if m.rule.control_ids else "none"
            click.echo(f"  [{m.rule.level}] {m.rule.title} | ATT&CK: {tags} | Controls: {cids}")

        click.echo(f"\n{len(matches)} matches found, logged to {jsonl_path}")
    else:
        click.echo("No matches found.")


@cli.command("sbom")
@click.argument("target")
@click.option("--output-dir", default="output", help="Directory to store SBOM file")
def sbom_cmd(target: str, output_dir: str) -> None:
    """Generate CycloneDX SBOM from a directory or container image."""
    from orchestrator.scanners.sbom import SbomGenerationError, SbomGenerator

    generator = SbomGenerator()
    try:
        result = generator.generate(target, output_dir)
        click.echo(f"SBOM generated: {result.sbom_path}")
        click.echo(f"Components: {result.components_count}")
        click.echo(f"Format: {result.format}")
    except SbomGenerationError as e:
        click.echo(f"SBOM generation failed: {e}", err=True)
        sys.exit(1)


@cli.command("container-scan")
@click.argument("image_ref")
@click.option("--product", required=True, help="Product name")
@click.option("--controls-dir", default=None)
@click.option("--tier-mappings", default=None)
@click.option("--output-jsonl", default=None)
def container_scan(
    image_ref: str,
    product: str,
    controls_dir: str | None,
    tier_mappings: str | None,
    output_jsonl: str | None,
) -> None:
    """Scan a container image for vulnerabilities using Grype."""
    baselines = controls_dir or _default_path("controls/baselines")
    mappings = tier_mappings or _default_path("controls/tier-mappings.yaml")
    jsonl_path = output_jsonl or _default_path("output/findings.jsonl")

    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    mapper = ControlMapper(repo)

    from orchestrator.scanners.grype import GrypeScanner

    grype = GrypeScanner(mapper)
    findings = grype.scan_image(image_ref)

    for f in findings:
        f.product = product

    writer = JsonlWriter(jsonl_path)
    writer.write_findings(findings)

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    click.echo(f"[container-scan] Image: {image_ref}")
    click.echo(f"[container-scan] {len(findings)} vulnerabilities found")
    for sev, count in sorted(severity_counts.items()):
        click.echo(f"  {sev}: {count}")
    click.echo(f"[container-scan] Findings logged to {jsonl_path}")


@cli.command()
@click.option("--product", required=True)
@click.option("--defectdojo-url", default="http://127.0.0.1:8080")
@click.option("--api-key", envvar="DD_API_KEY")
@click.option("--jsonl-path", default=None)
def sync(product: str, defectdojo_url: str, api_key: str | None, jsonl_path: str | None) -> None:
    """Sync JSONL findings to DefectDojo."""
    from orchestrator.integrations.defectdojo import DefectDojoClient

    jpath = jsonl_path or _default_path("output/findings.jsonl")

    if not api_key:
        click.echo("Error: --api-key or DD_API_KEY required", err=True)
        sys.exit(1)

    client = DefectDojoClient(base_url=defectdojo_url, api_key=api_key)

    if not client.health_check():
        click.echo(f"Warning: DefectDojo not reachable at {defectdojo_url}. Skipping sync.", err=True)
        click.echo("JSONL findings remain as backup (ADR-003).")
        return

    reader = JsonlWriter(jpath)
    entries = reader.read_findings(product=product)

    if not entries:
        click.echo(f"No findings for product '{product}' in {jpath}")
        return

    # Convert JSONL entries back to Finding objects
    findings: list[Finding] = []
    for entry in entries:
        data = entry.get("data", {})
        findings.append(
            Finding(
                source=data.get("source", ""),
                rule_id=data.get("rule_id", ""),
                severity=data.get("severity", ""),
                file=data.get("file", ""),
                line=data.get("line", 0),
                message=data.get("message", ""),
                control_ids=data.get("control_ids", []),
                product=data.get("product", ""),
            )
        )

    product_id = client.get_or_create_product(product)
    engagement_id = client.get_or_create_engagement(product_id, "pipeline-scan")
    result = client.import_findings(engagement_id, findings)

    click.echo(f"[sync] Synced {len(findings)} findings to DefectDojo")
    click.echo(f"       Product: {product} (id={product_id})")
    click.echo(f"       Created: {result['created']}, Skipped: {result['skipped']}, Errors: {result['errors']}")


@cli.command()
@click.option("--product", default=None, help="Filter by product name")
@click.option("--jsonl-path", default=None, help="JSONL path for override records")
def status(product: str | None, jsonl_path: str | None) -> None:
    """Show pending overrides and SLA status."""
    from orchestrator.resilience.override import OverrideManager

    jpath = jsonl_path or _default_path("output/findings.jsonl")
    writer = JsonlWriter(jpath)
    mgr = OverrideManager(writer)

    overrides = mgr.get_pending_overrides(product=product)

    if not overrides:
        click.echo("No pending overrides.")
        return

    click.echo("Pending overrides:")
    for o in overrides:
        click.echo(f"  {o.id} | {o.product} | {o.reason} | SLA: {o.deferred_scan_sla}")


@cli.command("threat-model")
@click.argument("target_path")
@click.option("--product", required=True)
@click.option("--output", default="output", help="Output directory")
def threat_model_cmd(target_path: str, product: str, output: str) -> None:
    """Generate threat model from real application components.

    Analyzes SBOM components + CVEs + product context to produce
    a threat model with concrete attack scenarios.
    """
    from orchestrator.intelligence.enricher import VulnerabilityEnricher
    from orchestrator.intelligence.epss import EpssClient
    from orchestrator.intelligence.threat_model import StaticThreatModelGenerator
    from orchestrator.scanners.grype import GrypeScanner
    from orchestrator.scanners.sbom import SbomGenerator

    # Load product manifest + controls
    prod_dir = _PROJECT_ROOT / "controls" / "products" / product
    manifest = load_manifest(str(prod_dir / "product-manifest.yaml"))

    baselines = _default_path("controls/baselines")
    mappings = _default_path("controls/tier-mappings.yaml")
    repo = ControlsRepository(baselines_dir=baselines, tier_mappings_path=mappings)
    repo.load_all()

    assessor = StaticRiskAssessor()
    tier = assessor.categorize(manifest)
    controls = select_baseline(repo, manifest, tier)

    mapper = ControlMapper(repo)

    # [1/4] SBOM generation
    click.echo("[1/4] SBOM generation")
    sbom_gen = SbomGenerator()
    sbom_result = sbom_gen.generate(target_path, output)
    raw_components = sbom_result.raw_sbom.get("components", [])
    components: list[dict[str, object]] = (
        raw_components if isinstance(raw_components, list) else []
    )
    component_names = [
        f"{c.get('name', '?')} {c.get('version', '?')}"
        for c in components
        if isinstance(c, dict)
    ]
    click.echo(f"      Components: {sbom_result.components_count}")

    # [2/4] Vulnerability scan + EPSS enrichment
    click.echo("[2/4] Vulnerability scan + EPSS enrichment")
    grype = GrypeScanner(mapper)
    findings = grype.scan(target_path)

    epss_client = EpssClient()
    enricher = VulnerabilityEnricher(epss_client, mapper)
    enriched = enricher.enrich(findings, manifest)
    enriched = enricher.sort_by_priority(enriched)

    epss_enriched = sum(1 for v in enriched if v.epss_score is not None)
    epss_critical = sum(1 for v in enriched if v.epss_score is not None and v.epss_score > 0.5)
    epss_high = sum(
        1 for v in enriched
        if v.epss_score is not None and 0.1 < v.epss_score <= 0.5
    )

    click.echo(f"      CVEs found: {len(findings)}")
    click.echo(f"      EPSS enriched: {epss_enriched}/{len(findings)}")
    click.echo(f"      CRITICAL (EPSS > 0.5): {epss_critical}")
    click.echo(f"      HIGH (EPSS > 0.1): {epss_high}")

    # [3/4] Threat model generation
    click.echo("[3/4] Threat model generation")
    generator = StaticThreatModelGenerator()
    threat_model = generator.generate(
        manifest=manifest,
        sbom_components=component_names,
        enriched_vulns=enriched,
        controls=controls,
    )

    click.echo(f"      Mode: {threat_model.mode}")
    click.echo(f"      Attack surface: {threat_model.attack_surface_summary}")
    click.echo(f"      Threat actors: {len(threat_model.threat_actors)}")
    click.echo(f"      Threat scenarios: {len(threat_model.threat_scenarios)}")

    # [4/4] Controls gap analysis
    click.echo("[4/4] Controls gap analysis")
    click.echo(f"      Required by threat model: {len(threat_model.controls_required)} controls")
    click.echo(f"      Currently covered: {len(threat_model.controls_covered)} controls")
    click.echo(f"      Gap: {len(threat_model.controls_gap)} controls")
    for gap_id in threat_model.controls_gap:
        click.echo(f"        - {gap_id}")

    # Write YAML output
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    yaml_file = output_path / f"threat-model-{product}.yaml"
    yaml_file.write_text(threat_model.to_yaml())

    click.echo(f"\nThreat model saved: {yaml_file}")


@cli.command()
@click.argument("target_path")
@click.option("--product", default="payment-api")
def demo(target_path: str, product: str) -> None:
    """Run the full MVP-0 demo."""
    from orchestrator.demo import run_demo

    run_demo(target_path, product)


def _build_scanners(mapper: ControlMapper) -> list:  # type: ignore[type-arg]
    """Build scanner instances. Imported lazily to avoid hard dep on CLI tools at import time."""
    from orchestrator.scanners.checkov import CheckovScanner
    from orchestrator.scanners.gitleaks import GitleaksScanner
    from orchestrator.scanners.grype import GrypeScanner
    from orchestrator.scanners.semgrep import SemgrepScanner

    return [
        CheckovScanner(mapper),
        SemgrepScanner(mapper),
        GrypeScanner(mapper),
        GitleaksScanner(mapper),
    ]
