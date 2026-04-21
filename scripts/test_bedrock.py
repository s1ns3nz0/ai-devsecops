#!/usr/bin/env python3
"""Live Bedrock integration test.

Usage:
    AWS_PROFILE=default BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0 python scripts/test_bedrock.py

This script:
1. Calls BedrockRiskAssessor.categorize() with the payment-api manifest
2. Calls BedrockRiskAssessor.assess() with sample findings
3. Prints the AI-generated narrative and recommendations
4. Saves the output to output/bedrock-test-output.json
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.assessor.bedrock import BedrockRiskAssessor
from orchestrator.assessor.bedrock_client import BedrockClient, BedrockInvocationError
from orchestrator.assessor.static import StaticRiskAssessor
from orchestrator.config.manifest import load_manifest
from orchestrator.controls.baseline import select_baseline
from orchestrator.controls.repository import ControlsRepository
from orchestrator.types import Finding


def _build_sample_findings() -> list[Finding]:
    """Build 5 representative findings for testing."""
    return [
        Finding(
            source="semgrep",
            rule_id="python.django.security.injection.sql-injection",
            severity="high",
            file="src/api/export.py",
            line=42,
            message="SQL injection via string concatenation in export query",
            control_ids=["PCI-DSS-6.3.1", "ASVS-V5.3.4"],
            product="payment-api",
        ),
        Finding(
            source="gitleaks",
            rule_id="aws-access-key",
            severity="critical",
            file="src/config/settings.py",
            line=15,
            message="Hardcoded AWS access key detected",
            control_ids=["PCI-DSS-3.5.1", "ASVS-V2.10.1"],
            product="payment-api",
        ),
        Finding(
            source="checkov",
            rule_id="CKV_AWS_19",
            severity="high",
            file="infra/s3.tf",
            line=3,
            message="S3 bucket without server-side encryption",
            control_ids=["PCI-DSS-3.4", "FISC-DATA-03"],
            product="payment-api",
        ),
        Finding(
            source="grype",
            rule_id="CVE-2023-49083",
            severity="high",
            file="requirements.txt",
            line=5,
            message="cryptography < 41.0.6 — use-after-free in PKCS7 parsing",
            control_ids=["PCI-DSS-6.3.1", "ASVS-V14.2.1"],
            product="payment-api",
        ),
        Finding(
            source="checkov",
            rule_id="CKV_AWS_23",
            severity="medium",
            file="infra/sg.tf",
            line=10,
            message="Security group allows ingress from 0.0.0.0/0",
            control_ids=["PCI-DSS-1.3.4", "FISC-NET-01"],
            product="payment-api",
        ),
    ]


def main() -> None:
    model_id = os.environ.get("BEDROCK_MODEL_ID")
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")

    if not model_id:
        print("ERROR: BEDROCK_MODEL_ID environment variable is not set.")
        print("Usage: BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6-20250514-v1:0 python scripts/test_bedrock.py")
        sys.exit(1)

    print(f"=== Bedrock Live Integration Test ===")
    print(f"Model: {model_id}")
    print(f"Region: {region}")
    print()

    # Load product manifest and controls
    manifest = load_manifest(str(PROJECT_ROOT / "controls/products/payment-api/product-manifest.yaml"))
    repo = ControlsRepository(
        baselines_dir=str(PROJECT_ROOT / "controls/baselines"),
        tier_mappings_path=str(PROJECT_ROOT / "controls/tier-mappings.yaml"),
    )
    repo.load_all()

    # Create assessors
    try:
        client = BedrockClient(model_id=model_id, region=region)
    except Exception as exc:
        print(f"ERROR: Failed to create BedrockClient: {exc}")
        print("Ensure boto3 is installed and AWS credentials are configured.")
        sys.exit(1)

    static = StaticRiskAssessor()
    bedrock = BedrockRiskAssessor(client=client, fallback=static)

    results: dict[str, object] = {"model_id": model_id, "region": region}

    # ── Test 1: categorize() ────────────────────────────────────
    print("[1/2] Testing categorize()...")
    try:
        t0 = time.monotonic()
        tier = bedrock.categorize(manifest)
        elapsed = time.monotonic() - t0
        print(f"      AI tier: {tier.value} ({elapsed:.2f}s)")

        static_tier = static.categorize(manifest)
        print(f"      Static tier: {static_tier.value}")
        print(f"      Match: {'YES' if tier == static_tier else 'NO (expected — AI may differ)'}")

        results["categorize"] = {
            "tier": tier.value,
            "static_tier": static_tier.value,
            "elapsed_seconds": round(elapsed, 2),
        }
    except BedrockInvocationError as exc:
        print(f"      FAILED: {exc}")
        results["categorize"] = {"error": str(exc)}

    print()

    # ── Test 2: assess() ────────────────────────────────────────
    print("[2/2] Testing assess()...")
    findings = _build_sample_findings()
    tier_for_controls = static.categorize(manifest)
    controls = select_baseline(repo, manifest, tier_for_controls)

    try:
        t0 = time.monotonic()
        report = bedrock.assess(findings, manifest, controls, "pre_merge")
        elapsed = time.monotonic() - t0

        print(f"      Risk score: {report.risk_score:.1f}/10 ({elapsed:.2f}s)")
        print(f"      Gate recommendation: {report.gate_recommendation} (advisory only)")
        print()
        print("      --- Narrative ---")
        for line in report.narrative.split(". "):
            print(f"      {line.strip()}.")
        print()

        # Static comparison
        static_report = static.assess(findings, manifest, controls, "pre_merge")
        print(f"      --- Static comparison ---")
        print(f"      Static risk score: {static_report.risk_score:.1f}/10")
        print(f"      Static narrative: {static_report.narrative[:120]}...")

        results["assess"] = {
            "risk_score": report.risk_score,
            "gate_recommendation": report.gate_recommendation,
            "narrative": report.narrative,
            "affected_controls": report.affected_controls,
            "elapsed_seconds": round(elapsed, 2),
            "static_risk_score": static_report.risk_score,
            "static_narrative": static_report.narrative,
        }
    except BedrockInvocationError as exc:
        print(f"      FAILED: {exc}")
        results["assess"] = {"error": str(exc)}

    # ── Save output ─────────────────────────────────────────────
    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "bedrock-test-output.json"
    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
