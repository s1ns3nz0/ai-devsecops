/* ============================================================
   Security Dashboard — Split-Panel SPA with Hash Router
   Pure JS, no frameworks. Fetches JSON from same origin.
   ============================================================ */

// ---- Sample / Fallback Data ----

var SAMPLE_PROJECTS = {
    projects: [
        {
            id: "payment-api",
            name: "Payment API",
            repo: "s1ns3nz0/ai-devsecops",
            repo_url: "https://github.com/s1ns3nz0/ai-devsecops",
            frameworks: ["PCI DSS 4.0", "ASVS 4.0.3", "FISC Safety"],
            data_classification: ["PCI", "PII"],
            tier: "critical",
            last_scan: "2026-05-04T09:32:17Z",
            gate: "DATO",
            findings_summary: { critical: 1, high: 9, medium: 10, low: 7 }
        }
    ]
};

var SAMPLE_INDEX = {
    metadata: {
        timestamp: "2026-05-04T09:32:17Z",
        system: "payment-api",
        mode: "hybrid",
        version: "0.3.0"
    },
    gate: {
        decision: "DATO",
        rationale: "1 very-high and 4 high residual risks exceed threshold. 31 controls other-than-satisfied.",
        thresholds: { very_high_max: 0, high_max: 2 },
        actual: { very_high: 1, high: 4, moderate: 8, low: 6, very_low: 3 }
    },
    risk_posture: {
        total_findings: 27,
        assessed: 6,
        distribution: {
            "very-high": 1,
            "high": 4,
            "moderate": 9,
            "low": 9,
            "very-low": 4
        }
    },
    sar_summary: {
        total_controls: 102,
        satisfied: 38,
        other_than_satisfied: 31,
        not_assessed: 33,
        coverage_pct: 37.3
    },
    poam_summary: {
        total_items: 12,
        by_severity: { critical: 1, high: 4, medium: 5, low: 2 },
        overdue: 2,
        next_deadline: "2026-05-11T00:00:00Z"
    },
    pipeline: {
        total_duration_ms: 119150,
        phases: [
            {
                name: "DEVELOP",
                risk_snapshot: { posture: "moderate", confidence: 40, threats_identified: 2, new_threats: 2, confirmed: 0, note: "2 threats identified from code analysis. TE-001 (SQLi) theoretical — SAST found patterns but no runtime confirmation yet. TE-002 (credentials) confirmed in Docker layers." },
                steps: [
                    { id: "sast", tool: "SAST", scanner: "Semgrep", version: "1.67.0", status: "completed", findings: 4, breakdown: { high: 1, medium: 2, low: 1 }, duration_ms: 12400, rules_run: 847, files_scanned: 156, detail: "Code analysis across Python, JS, and IaC files. 847 rules evaluated against 156 source files." },
                    { id: "secrets", tool: "Secrets", scanner: "Gitleaks", version: "8.18.0", status: "completed", findings: 1, breakdown: { high: 1 }, duration_ms: 3100, commits_scanned: 342, detail: "Git history scan across 342 commits. 1 hardcoded credential detected in Docker build layer." }
                ]
            },
            {
                name: "BUILD",
                risk_snapshot: { posture: "high", confidence: 65, threats_identified: 4, new_threats: 2, confirmed: 1, note: "Risk elevated to HIGH. +2 new threats: TE-003 (IAM over-permission) from IaC scan, TE-004 (CVE-2026-0778) from dependency scan. TE-002 credential exposure confirmed in container image layers." },
                steps: [
                    { id: "sca", tool: "SCA", scanner: "Grype", version: "0.79.0", status: "completed", findings: 13, breakdown: { critical: 1, high: 5, medium: 4, low: 3 }, duration_ms: 8200, packages_scanned: 214, sbom_format: "CycloneDX 1.5", detail: "Dependency scan of 214 packages from CycloneDX SBOM. 13 known CVEs matched against NVD + GitHub Advisory DB." },
                    { id: "iac", tool: "IaC", scanner: "Checkov", version: "3.2.0", status: "completed", findings: 4, breakdown: { high: 2, medium: 2 }, duration_ms: 15600, checks_run: 1243, resources_scanned: 47, detail: "Infrastructure-as-code analysis of 47 Terraform resources. 1243 policy checks evaluated." },
                    { id: "epss", tool: "EPSS", scanner: "FIRST.org", version: "v2026-05-04", status: "completed", findings: 13, breakdown: { enriched: 13, total_cves: 13 }, duration_ms: 2100, detail: "Exploit Prediction Scoring System enrichment. 13 of 13 CVEs matched. Highest: CVE-2026-0778 at 0.42 (72nd percentile)." }
                ]
            },
            {
                name: "TEST",
                accent: true,
                risk_snapshot: { posture: "high", confidence: 90, threats_identified: 6, new_threats: 2, confirmed: 3, note: "TE-001 (SQLi) CONFIRMED by DAST — runtime exploitation verified. +1 new: TE-005 (missing mTLS). +1 structural: TE-006 (RDS failover). Risk remains HIGH but confidence now 90% — evidence from both static and dynamic analysis." },
                steps: [
                    { id: "dast", tool: "DAST", scanner: "ZAP", version: "2.15.0", status: "completed", findings: 5, breakdown: { high: 2, low: 2, informational: 1 }, duration_ms: 45200, endpoints_scanned: 5, openapi_spec: "openapi.yaml", detail: "API scan against running payment-api container using OpenAPI 3.0.3 spec. SQL injection and reflected XSS confirmed in /api/export." },
                    { id: "ai-assess", tool: "AI Assessment", scanner: "Claude Sonnet", version: "4.6", status: "completed", findings: 6, breakdown: { "very-high": 1, high: 3, moderate: 2 }, duration_ms: 32100, mode: "hybrid", tokens_input: 14200, tokens_output: 5640, cache_hit_rate: "42%", detail: "SP 800-30 risk assessment synthesizing all prior stage evidence. 5 adversarial + 1 structural threat events. Cross-signal correlation: SAST+DAST confirmed SQLi chain." }
                ]
            },
            {
                name: "DECISION",
                risk_snapshot: { posture: "high", confidence: 92, threats_identified: 6, new_threats: 0, confirmed: 3, note: "Gate evaluation against YAML thresholds + OPA policies. DATO: max_critical_findings violated (1 found, 0 allowed), max_secrets_detected violated (1 found, 0 allowed)." },
                steps: [
                    { id: "gate", tool: "Gate", scanner: "OPA + Threshold", version: "OPA 0.64", status: "blocked", findings: 2, breakdown: { violations: 2 }, duration_ms: 450, policies_evaluated: 4, detail: "YAML threshold + OPA/Rego gate evaluation. 4 policies checked. BLOCKED on 2 violations." }
                ]
            }
        ]
    }
};

var SAMPLE_OVERRIDES = [
    {
        finding_id: "CVE-2026-0778",
        override_type: "accept",
        scanner: "Grype",
        severity: "high",
        justification: "Mitigated by WAF rule WR-2026-042. Container not internet-facing.",
        authorized_by: "jsyang",
        authorized_at: "2026-05-04",
        expires: "2026-08-04",
        conditions: ["WAF rule must remain active"]
    },
    {
        finding_id: "CKV_AWS_18",
        override_type: "defer",
        scanner: "Checkov",
        severity: "medium",
        justification: "Scheduled for Q3 sprint. Low exposure -- internal bucket only.",
        authorized_by: "jsyang",
        authorized_at: "2026-05-01",
        expires: "2026-07-01",
        conditions: ["Must be resolved by Q3"]
    }
];

var SAMPLE_COMPLIANCE = {
    frameworks: [
        {
            id: "pci-dss-4.0",
            name: "PCI DSS 4.0",
            satisfied: 18,
            total: 47,
            controls: [
                {
                    id: "PCI-DSS-6.2.4",
                    title: "Software engineering techniques prevent common attacks",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "high", scanner: "Semgrep", message: "sql-injection in payment.py:42", override: null },
                        { severity: "high", scanner: "ZAP", message: "SQL Injection — GET /api/export (param: query) [CWE-89]", override: null },
                        { severity: "high", scanner: "ZAP", message: "Cross Site Scripting (Reflected) — GET /api/export (param: query) [CWE-79]", override: null },
                        { severity: "medium", scanner: "Semgrep", message: "nosql-injection in user.py:88", override: null }
                    ]
                },
                {
                    id: "PCI-DSS-6.3.1",
                    title: "Known Vulnerabilities Addressed",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "high", scanner: "Grype", message: "CVE-2026-0778 OpenSSL 3.1.2 buffer overflow", override: { type: "accept", expires: "2026-08-04" } },
                        { severity: "medium", scanner: "Checkov", message: "CKV_AWS_18 S3 bucket without encryption", override: { type: "defer", expires: "2026-07-01" } }
                    ]
                },
                {
                    id: "PCI-DSS-7.2.2",
                    title: "Access Assigned Based on Job Classification",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "high", scanner: "Checkov", message: "Overly permissive IAM role allows s3:*", override: null },
                        { severity: "high", scanner: "Checkov", message: "Lambda execution role with admin permissions", override: null }
                    ]
                },
                { id: "PCI-DSS-8.3.1", title: "Unique IDs for User Authentication", status: "satisfied", findings: [] },
                { id: "PCI-DSS-4.2.1", title: "Strong Cryptography for Transmission", status: "other-than-satisfied", findings: [
                    { severity: "medium", scanner: "Semgrep", message: "Missing mTLS on internal service calls", override: null }
                ]},
                { id: "PCI-DSS-6.3.2", title: "Custom Software Inventory Maintained", status: "other-than-satisfied", findings: [
                    { severity: "high", scanner: "Grype", message: "CVE-2026-0778 in OpenSSL 3.1.2", override: { type: "accept", expires: "2026-08-04" } }
                ]},
                { id: "PCI-DSS-10.2.1", title: "Audit Logs Capture Individual User Access", status: "not-assessed", findings: [] },
                { id: "PCI-DSS-3.5.1", title: "PAN Rendered Unreadable in Storage", status: "satisfied", findings: [] },
                { id: "PCI-DSS-2.2.1", title: "System Configuration Standards Applied", status: "satisfied", findings: [] }
            ]
        },
        {
            id: "asvs-4.0.3",
            name: "OWASP ASVS 4.0.3",
            satisfied: 15,
            total: 42,
            controls: [
                {
                    id: "ASVS-V5.1.3",
                    title: "Input Validated Using Positive Validation",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "high", scanner: "Semgrep", message: "Unvalidated input in query builder", override: null },
                        { severity: "high", scanner: "ZAP", message: "SQL Injection — GET /api/export (param: query) [CWE-89]", override: null },
                        { severity: "medium", scanner: "ZAP", message: "X-Content-Type-Options Header Missing — POST /api/login [CWE-693]", override: null }
                    ]
                },
                {
                    id: "ASVS-V9.1.1",
                    title: "TLS Used for All Client Connectivity",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "medium", scanner: "Semgrep", message: "HTTP used for internal service calls", override: null }
                    ]
                },
                { id: "ASVS-V1.2.1", title: "Authentication Architecture Documented", status: "satisfied", findings: [] },
                { id: "ASVS-V2.4.1", title: "Password Hashing Using Approved Algorithm", status: "satisfied", findings: [] },
                { id: "ASVS-V3.1.1", title: "Session Token Generation Uses CSPRNG", status: "not-assessed", findings: [] }
            ]
        },
        {
            id: "fisc-safety",
            name: "FISC Safety Standards",
            satisfied: 5,
            total: 13,
            controls: [
                {
                    id: "FISC-\u5B9F15",
                    title: "Encryption Standards",
                    status: "other-than-satisfied",
                    findings: [
                        { severity: "medium", scanner: "Semgrep", message: "Weak cipher suite in TLS config", override: null }
                    ]
                },
                { id: "FISC-\u5B9F10", title: "Access Control Standards", status: "satisfied", findings: [] },
                { id: "FISC-\u5B9F20", title: "Vulnerability Management", status: "satisfied", findings: [] },
                { id: "FISC-\u5B9F25", title: "Incident Response Procedures", status: "not-assessed", findings: [] }
            ]
        }
    ]
};

var SAMPLE_RISK_ASSESSMENT = {
    prepare: {
        purpose: "Identify and evaluate information security risks to the payment-api system to inform authorization decisions and prioritize risk responses in accordance with organizational risk tolerance.",
        scope: {
            tier: "Tier 3 \u2014 Information System",
            system: "payment-api",
            boundary: "EKS cluster (payment namespace), RDS PostgreSQL, S3 storage, API Gateway, Lambda functions",
            time_frame: "Valid for 90 days from assessment date or until significant system change",
            applicability: "Production environment, Tokyo region (ap-northeast-1)"
        },
        assumptions: [
            "All automated scanners ran successfully and produced complete results",
            "SBOM (CycloneDX 1.5) accurately represents deployed dependencies",
            "EPSS scores reflect current exploit landscape as of assessment date",
            "Container images analyzed match those deployed in production"
        ],
        constraints: [
            "DAST scanning was not performed (no running endpoint available)",
            "Manual code review was not conducted \u2014 findings are scanner-based only",
            "Threat intelligence is limited to public sources (NVD, EPSS, GHSA)"
        ],
        risk_model: "Semi-quantitative, threat-oriented (SP 800-30 Table I-2/I-3)",
        assessment_approach: "Semi-quantitative using 5-level qualitative scale mapped to 0-100 semi-quantitative bins",
        analysis_approach: "Threat-oriented with MITRE ATT&CK mapping",
        assessment_type: "Subsequent assessment \u2014 updates prior baseline from 2026-04-30",
        information_sources: [
            { source: "Semgrep", type: "SAST", description: "Static analysis of application source code" },
            { source: "Grype", type: "SCA", description: "Dependency vulnerability scanning against NVD + GHSA" },
            { source: "Gitleaks", type: "Secrets", description: "Git history credential detection" },
            { source: "Checkov", type: "IaC", description: "Infrastructure-as-code policy evaluation" },
            { source: "FIRST.org EPSS", type: "Threat Intelligence", description: "Exploit prediction scoring" },
            { source: "NIST NVD", type: "Vulnerability Database", description: "CVE details and CVSS scores" }
        ]
    },
    executive_summary: "The payment-api system faces significant risk from multiple attack vectors targeting its transaction processing and data storage layers. The most critical finding is a chain of SQL injection vulnerabilities in the payment endpoints \u2014 confirmed by both SAST (Semgrep) and DAST (ZAP) scanning \u2014 combined with overly permissive IAM roles, which together could enable an attacker to exfiltrate cardholder data from the PCI-scoped environment. The presence of hardcoded credentials in Docker image layers further amplifies this risk by providing potential lateral movement paths. While the OpenSSL vulnerability (CVE-2026-0778) has a high EPSS score (0.42), its exploitability is constrained by the container's network configuration. Additionally, a non-adversarial structural risk exists: RDS database failover during peak transaction load could halt payment processing for 60-120 seconds, potentially violating the 99.95% SLA. Immediate remediation priority should focus on the SQLi + IAM permission escalation chain, followed by credential rotation, image hardening, and database resilience improvements.",
    cross_signal_insights: [
        "SQL injection (TE-001) + overly permissive IAM (TE-003) create a chained attack path: SQLi provides initial access, IAM s3:* allows data exfiltration from S3 buckets containing PII backups.",
        "Hardcoded API keys (TE-002) in Docker layers are extractable via public registry. Combined with missing mTLS (TE-005), compromised keys could intercept inter-service traffic without detection.",
        "CVE-2026-0778 (TE-004) has public exploit code but the EPSS probability (0.42) suggests moderate active exploitation. The container's non-internet-facing posture reduces effective likelihood from high to moderate."
    ],
    overall_risk_posture: "high",
    threat_events: [
        {
            id: "TE-001",
            title: "SQL Injection via Unvalidated Payment Parameters",
            threat_source: { type: "adversarial", name: "External attacker (organized crime)", capability: "high", intent: "Financial gain via cardholder data theft", targeting: "Targeted \u2014 payment processing endpoints" },
            mitre_technique: "T1190",
            mitre_name: "Exploit Public-Facing Application",
            risk_level: "very-high",
            relevance: "confirmed",
            discovered_at: "develop",
            likelihood: { initiation: "high", impact: "very-high", overall: "high", epss: null, evidence: "3 distinct injection vectors found by Semgrep. Payment endpoints are internet-facing with no WAF SQLi rules." },
            impact: { severity: "very-high", impact_type: "harm to operations", cia: { confidentiality: "high", integrity: "high", availability: "moderate" }, business: "Direct access to PCI cardholder data environment. Potential PCI DSS non-compliance triggering Level 1 assessment." },
            risk_score: 96,
            vulnerabilities: [
                { id: "VULN-001", description: "Parameterized queries not enforced in payment service", severity: "high" },
                { id: "VULN-002", description: "No input validation middleware on API gateway", severity: "high" }
            ],
            predisposing_conditions: [
                "Internet-facing payment endpoints with no WAF",
                "PCI cardholder data environment directly accessible from application tier",
                "No prepared statement enforcement at ORM level"
            ],
            uncertainty: "low",
            sources: ["Semgrep"],
            response: { type: "mitigate", description: "Enforce parameterized queries via ORM-only data access pattern. Deploy WAF rules for SQLi signatures. Schedule penetration test within 14 days.", deadline: "2026-05-11", milestones: ["Deploy ORM migration", "Enable WAF SQLi ruleset", "Complete pentest"] },
            controls: ["PCI-DSS-6.2.4", "ASVS-V5.1.3", "ASVS-V5.3.4"],
            narrative: "Automated scanning detected 3 SQL injection vectors in payment processing endpoints. Parameterized queries are not consistently enforced across the transaction service layer."
        },
        {
            id: "TE-002",
            title: "Hardcoded API Keys in Container Image Layers",
            threat_source: { type: "adversarial", name: "Insider threat / supply chain", capability: "moderate", intent: "Credential harvesting for lateral movement", targeting: "Opportunistic \u2014 public container registry" },
            mitre_technique: "T1552.001",
            mitre_name: "Credentials In Files",
            risk_level: "high",
            relevance: "confirmed",
            discovered_at: "develop",
            confirmed_at: "build",
            likelihood: { initiation: "high", impact: "high", overall: "high", epss: null, evidence: "1 API key and 1 DB connection string found in intermediate Docker layers by Gitleaks." },
            impact: { severity: "high", impact_type: "harm to assets", cia: { confidentiality: "high", integrity: "moderate", availability: "low" }, business: "Compromised credentials enable lateral movement to database tier. Risk of unauthorized data access." },
            risk_score: 80,
            vulnerabilities: [
                { id: "VULN-003", description: "Multi-stage Docker build not used \u2014 secrets in intermediate layers", severity: "high" }
            ],
            predisposing_conditions: [
                "Container images published to registry without layer scanning",
                "No secret rotation policy enforced"
            ],
            uncertainty: "low",
            sources: ["Gitleaks"],
            response: { type: "mitigate", description: "Rotate all exposed credentials immediately. Implement multi-stage Docker builds with secret mounting. Add Gitleaks to CI gate.", deadline: "2026-05-08", milestones: ["Rotate credentials", "Refactor Dockerfile", "Update CI gate"] },
            controls: ["PCI-DSS-6.3.2", "ASVS-V2.5.4"],
            narrative: "Gitleaks analysis of container layers revealed 2 hardcoded API keys and 1 database connection string embedded in intermediate build layers."
        },
        {
            id: "TE-003",
            title: "Overly Permissive IAM Role Allows S3 Data Exfiltration",
            threat_source: { type: "adversarial", name: "External attacker via compromised credentials", capability: "high", intent: "Data exfiltration of PII/financial records", targeting: "Targeted \u2014 S3 buckets with customer data" },
            mitre_technique: "T1530",
            mitre_name: "Data from Cloud Storage",
            risk_level: "high",
            relevance: "expected",
            discovered_at: "build",
            likelihood: { initiation: "moderate", impact: "very-high", overall: "high", epss: null, evidence: "Checkov identified IAM policy with s3:* permissions. Combined with SSRF, enables full S3 enumeration." },
            impact: { severity: "very-high", impact_type: "harm to individuals", cia: { confidentiality: "very-high", integrity: "low", availability: "low" }, business: "Full S3 bucket access exposes stored PII. Regulatory notification required under APPI and GDPR." },
            risk_score: 80,
            vulnerabilities: [
                { id: "VULN-004", description: "IAM policy uses wildcard (s3:*) instead of least-privilege", severity: "high" },
                { id: "VULN-005", description: "No S3 bucket policy restricting access by VPC endpoint", severity: "medium" }
            ],
            predisposing_conditions: [
                "Shared VPC with multiple services having broad network access",
                "No S3 access logging enabled"
            ],
            uncertainty: "moderate",
            sources: ["Checkov"],
            response: { type: "mitigate", description: "Apply least-privilege IAM policy scoped to specific bucket ARNs with read-only actions. Enable S3 access logging.", deadline: "2026-05-14", milestones: ["Scope IAM policy", "Enable S3 logging", "Verify with Checkov"] },
            controls: ["PCI-DSS-7.2.2", "PCI-DSS-7.2.1", "ASVS-V1.4.4"],
            narrative: "Checkov identified IAM policy with s3:* permissions attached to the payment-api execution role. Combined with potential SSRF, this enables full S3 bucket enumeration and download."
        },
        {
            id: "TE-004",
            title: "Known CVE in Base Image: OpenSSL Buffer Overflow",
            threat_source: { type: "adversarial", name: "External attacker (opportunistic)", capability: "moderate", intent: "Remote code execution", targeting: "Untargeted \u2014 automated scanning for known CVEs" },
            mitre_technique: "T1203",
            mitre_name: "Exploitation for Client Execution",
            risk_level: "high",
            relevance: "predicted",
            discovered_at: "build",
            likelihood: { initiation: "moderate", impact: "high", overall: "moderate", epss: 0.42, evidence: "CVE-2026-0778 (CVSS 8.1) in OpenSSL 3.1.2. Public exploit available. EPSS 0.42 (72nd percentile)." },
            impact: { severity: "high", impact_type: "harm to operations", cia: { confidentiality: "high", integrity: "high", availability: "moderate" }, business: "Remote code execution within container. Could pivot to other services in the mesh." },
            risk_score: 64,
            vulnerabilities: [
                { id: "VULN-006", description: "OpenSSL 3.1.2 with known buffer overflow (CVE-2026-0778)", severity: "high" }
            ],
            predisposing_conditions: [
                "Base image not pinned to patched version",
                "No automated image rebuild pipeline on CVE disclosure"
            ],
            uncertainty: "moderate",
            sources: ["Grype", "EPSS"],
            response: { type: "mitigate", description: "Update base image to python:3.11-slim-bookworm with OpenSSL 3.1.5. Add image scanning to CI pipeline.", deadline: "2026-05-10", milestones: ["Update base image", "Rebuild containers", "Deploy to staging"] },
            controls: ["PCI-DSS-6.3.1", "ASVS-V14.2.1"],
            narrative: "Grype detected CVE-2026-0778 (CVSS 8.1) in OpenSSL 3.1.2 bundled in the python:3.11-slim base image. Public exploit code is available."
        },
        {
            id: "TE-005",
            title: "Missing TLS Certificate Validation on Internal Service Mesh",
            threat_source: { type: "adversarial", name: "Insider / adjacent network attacker", capability: "low", intent: "Interception of sensitive data in transit", targeting: "Opportunistic \u2014 unencrypted internal traffic" },
            mitre_technique: "T1557",
            mitre_name: "Adversary-in-the-Middle",
            risk_level: "moderate",
            relevance: "possible",
            discovered_at: "test",
            likelihood: { initiation: "low", impact: "high", overall: "low", epss: null, evidence: "Service-to-service HTTP without mTLS. Requires network-level access to shared VPC subnet." },
            impact: { severity: "high", impact_type: "harm to operations", cia: { confidentiality: "high", integrity: "moderate", availability: "low" }, business: "Interception of fraud scoring data and payment tokens in transit." },
            risk_score: 40,
            vulnerabilities: [
                { id: "VULN-007", description: "Service mesh mTLS not enabled \u2014 HTTP used for inter-service communication", severity: "medium" }
            ],
            predisposing_conditions: [
                "Shared VPC subnet with multiple tenants",
                "No network segmentation between services"
            ],
            uncertainty: "high",
            sources: ["Semgrep"],
            response: { type: "accept", description: "Accept with conditions \u2014 Enable service mesh mTLS (Istio strict mode) in next sprint. Monitor network flows.", deadline: "2026-05-21", milestones: ["Enable Istio strict mode", "Monitor unencrypted flows"] },
            controls: ["PCI-DSS-4.2.1", "ASVS-V9.1.1", "FISC-\u5B9F15"],
            narrative: "Service-to-service communication between payment-api and fraud-detection-service uses HTTP without mTLS. Traffic traverses shared VPC subnet."
        },
        {
            id: "TE-006",
            title: "RDS Database Failover During Peak Transaction Load",
            threat_source: { type: "structural", name: "System component failure", capability: "n/a", intent: "n/a", targeting: "n/a" },
            mitre_technique: "",
            mitre_name: "",
            range_of_effects: "Transaction processing halted for 60-120s. SQS queue backlog. SLA violation if uptime drops below 99.95%.",
            risk_level: "moderate",
            relevance: "possible",
            discovered_at: "test",
            likelihood: { initiation: "n/a", impact: "moderate", overall: "moderate", epss: null, evidence: "RDS Multi-AZ failover takes 60-120s. During failover, payment transactions queue in SQS but may exceed timeout thresholds." },
            impact: { severity: "moderate", impact_type: "harm to operations", cia: { confidentiality: "low", integrity: "moderate", availability: "high" }, business: "Transaction processing halted for 60-120s during failover. SLA violation if >99.95% uptime not met. Revenue impact estimated at $2,400/minute." },
            risk_score: 50,
            vulnerabilities: [
                { id: "VULN-008", description: "No circuit breaker pattern on database connection layer", severity: "medium" }
            ],
            predisposing_conditions: [
                "Single RDS instance without read replicas for transaction load distribution",
                "No connection pooling via RDS Proxy"
            ],
            uncertainty: "moderate",
            sources: ["Architecture Review"],
            response: { type: "mitigate", description: "Implement circuit breaker pattern with SQS dead letter queue. Configure RDS Proxy for connection pooling during failover. Conduct quarterly failover testing.", deadline: "2026-06-15", milestones: ["Deploy circuit breaker", "Configure RDS Proxy", "Schedule failover drill"] },
            controls: ["PCI-DSS-12.10.1", "FISC-\u5B9F20"],
            narrative: "Non-adversarial structural risk: RDS database failover during peak transaction periods could interrupt payment processing for 60-120 seconds, potentially violating SLA commitments."
        }
    ],
    appendix: {
        methodology_reference: "NIST SP 800-30 Rev 1 (September 2012)",
        assessment_team: [
            { role: "Automated Assessment Engine", name: "AI DevSecOps Platform v0.3.0" },
            { role: "Risk Assessor (AI)", name: "Claude Sonnet 4.6 via AWS Bedrock" },
            { role: "Authorizing Official", name: "To be designated" }
        ],
        related_documents: [
            "NIST SP 800-37 Rev 2 \u2014 Risk Management Framework",
            "NIST SP 800-53 Rev 5 \u2014 Security and Privacy Controls",
            "FIPS 199 \u2014 Standards for Security Categorization",
            "PCI DSS v4.0 \u2014 Payment Card Industry Data Security Standard"
        ]
    }
};

var SAMPLE_ASSETS = [
    {
        id: "AST-001", name: "Payment Processing",
        description: "Core transaction processing logic",
        owner: "Backend Team",
        components: ["EKS pods", "Lambda"],
        data_types: ["PCI", "PII"],
        cia: { confidentiality: "high", integrity: "high", availability: "high" },
        sla: "99.95% uptime",
        threat_events: ["TE-001", "TE-004"],
        aggregate_risk: "very-high"
    },
    {
        id: "AST-002", name: "Data Storage",
        description: "RDS PostgreSQL, S3 backup, DynamoDB sessions",
        owner: "Cloud Infra",
        components: ["RDS", "S3", "DynamoDB"],
        data_types: ["PCI", "PII"],
        cia: { confidentiality: "high", integrity: "high", availability: "moderate" },
        sla: "RPO <1min, RTO <5min",
        threat_events: ["TE-001", "TE-003", "TE-006"],
        aggregate_risk: "high"
    },
    {
        id: "AST-003", name: "API Boundary",
        description: "Public-facing API Gateway and ALB",
        owner: "Platform Team",
        components: ["API Gateway", "ALB"],
        data_types: ["PCI"],
        cia: { confidentiality: "moderate", integrity: "moderate", availability: "high" },
        sla: "99.99% availability",
        threat_events: ["TE-001", "TE-005"],
        aggregate_risk: "high"
    },
    {
        id: "AST-004", name: "Credential Management",
        description: "API keys, DB connections, service tokens",
        owner: "DevOps",
        components: ["Docker layers", "Env vars"],
        data_types: ["Credentials"],
        cia: { confidentiality: "high", integrity: "high", availability: "low" },
        sla: "24h rotation on compromise",
        threat_events: ["TE-002"],
        aggregate_risk: "high"
    },
    {
        id: "AST-005", name: "Infrastructure",
        description: "IAM policies, VPC, service mesh",
        owner: "Cloud Infra",
        components: ["IAM", "VPC", "Service mesh"],
        data_types: [],
        cia: { confidentiality: "low", integrity: "moderate", availability: "moderate" },
        sla: "1 business day review",
        threat_events: ["TE-003", "TE-005"],
        aggregate_risk: "moderate"
    }
];

var SAMPLE_STAKEHOLDER_ACTIONS = {
    develop: {
        mission_impact: {
            revenue: "Potential exposure of payment processing logic. SQLi vectors could enable unauthorized transactions.",
            sla: "No direct SLA impact at this stage -- code not yet deployed.",
            regulatory: "Credential in Docker layers: potential APPI violation if PII-accessing credentials are compromised.",
            supply_chain: "No supply chain impact identified at develop stage."
        },
        stakeholders: [
            { role: "Backend Team Lead", finding: "3 SQL injection patterns in payment.py", urgency: "high", action: "Refactor payment service to use ORM-only data access. Target: before next sprint merge.", poam: "POAM-001" },
            { role: "DevOps", finding: "Hardcoded credential in Docker layer", urgency: "immediate", action: "Rotate exposed API key. Implement multi-stage Docker build with secret mounting.", poam: "POAM-002", decision: null }
        ],
        reassessment: {
            next_review: "2026-08-04",
            monitoring: true,
            monitoring_detail: "CI runs SAST + secrets scan on every PR",
            triggers: [
                "New SAST rules added to Semgrep configuration",
                "Codebase refactor affecting payment processing module",
                "New developer onboarded to payment service team"
            ]
        }
    },
    build: {
        mission_impact: {
            revenue: "$2,400/min revenue at risk if payment processing compromised via dependency exploit.",
            sla: "99.95% uptime SLA at risk -- IAM misconfiguration could enable data exfiltration causing service suspension.",
            regulatory: "PII in S3 buckets accessible via s3:* IAM policy. APPI/GDPR notification required within 72h if breached.",
            supply_chain: "CVE-2026-0778 in OpenSSL 3.1.2 affects all deployments using python:3.11-slim base image."
        },
        stakeholders: [
            { role: "CISO", finding: "IAM over-permission enables S3 data exfiltration (TE-003)", urgency: "high", action: "Review and approve IAM policy scoping plan. Accept, mitigate, or escalate?", poam: "POAM-003", decision: "Approve IAM remediation plan by May 8" },
            { role: "DevOps", finding: "CVE-2026-0778 in base image (TE-004)", urgency: "medium", action: "Update base image to python:3.11-slim-bookworm with OpenSSL 3.1.5.", poam: "POAM-004", decision: null },
            { role: "Cloud Infra", finding: "s3:* wildcard IAM + no access logging", urgency: "high", action: "Scope IAM policy to specific S3 ARNs. Enable S3 access logging.", poam: "POAM-003,POAM-006", decision: null },
            { role: "Legal/DPO", finding: "PII exposure risk via S3 bucket access", urgency: "high", action: "Assess APPI/GDPR notification obligation. No action unless breach confirmed.", poam: null, decision: "Confirm notification threshold with legal counsel" }
        ],
        reassessment: {
            next_review: "2026-08-04",
            monitoring: true,
            monitoring_detail: "SCA runs on every build. EPSS scores updated daily.",
            triggers: [
                "New dependency added or major version updated",
                "Base image changed or rebuilt",
                "EPSS score for any tracked CVE exceeds 0.5",
                "SBOM composition change detected by Dependency-Track"
            ]
        }
    },
    test: {
        mission_impact: {
            revenue: "$2,400/min revenue at risk -- CONFIRMED by DAST. SQL injection exploitable at runtime.",
            sla: "99.95% uptime at risk from two vectors: exploitable SQLi (adversarial) + RDS failover (structural).",
            regulatory: "PCI DSS non-compliance confirmed: 6 controls other-than-satisfied. Level 1 assessment may be triggered.",
            supply_chain: "Container image with known CVE deployed to registry. All downstream consumers affected."
        },
        stakeholders: [
            { role: "CISO", finding: "SQLi CONFIRMED by DAST + IAM chain = data exfiltration path", urgency: "immediate", action: "Escalate to executive risk review. Block release until POAM-001 resolved.", poam: "POAM-001", decision: "Approve emergency remediation sprint" },
            { role: "Authorizing Official", finding: "DATO -- 2 gate violations", urgency: "high", action: "Review override requests. Approve ATO-with-conditions or maintain DATO.", poam: null, decision: "Authorization decision required by May 11" },
            { role: "Platform Team", finding: "Missing mTLS on service mesh (TE-005)", urgency: "medium", action: "Enable Istio strict mode in next sprint.", poam: "POAM-005", decision: null },
            { role: "Product Owner", finding: "Revenue impact: $2,400/min + SLA penalty risk", urgency: "info", action: "Prioritize security remediation in sprint backlog. Communicate risk to business stakeholders.", poam: null, decision: null },
            { role: "SRE/Reliability", finding: "RDS failover during peak load (TE-006)", urgency: "medium", action: "Implement circuit breaker pattern. Configure RDS Proxy. Schedule failover drill.", poam: null, decision: null }
        ],
        reassessment: {
            next_review: "2026-08-04",
            monitoring: true,
            monitoring_detail: "DAST runs on every merge to main. Runtime monitoring via CloudWatch.",
            triggers: [
                "New API endpoints added to OpenAPI spec",
                "Penetration test scheduled or completed",
                "Security incident or near-miss reported",
                "PCI DSS assessment cycle (quarterly)"
            ]
        }
    },
    decision: {
        mission_impact: {
            revenue: "$2,400/min at risk. Gate BLOCKED -- no production release until critical findings resolved.",
            sla: "SLA not currently impacted -- DATO prevents deployment of vulnerable code.",
            regulatory: "PCI DSS compliance gap: 31 controls other-than-satisfied. ATO cannot be granted.",
            supply_chain: "Release blocked. No downstream impact."
        },
        stakeholders: [
            { role: "Authorizing Official", finding: "DATO: max_critical_findings (1) + max_secrets_detected (1)", urgency: "immediate", action: "Review 2 active overrides. Decide: maintain DATO, or approve ATO-with-conditions pending POA&M completion.", poam: null, decision: "Authorization decision required" },
            { role: "CISO", finding: "Overall risk posture: HIGH (92% confidence)", urgency: "high", action: "Present risk assessment to executive committee. Recommend remediation timeline.", poam: null, decision: "Accept residual risk or mandate remediation sprint" },
            { role: "Engineering Manager", finding: "12 POA&M items, 2 overdue", urgency: "high", action: "Allocate sprint capacity for security remediation. Prioritize POAM-001 (SQLi) and POAM-002 (credentials).", poam: "POAM-001,POAM-002", decision: null }
        ],
        reassessment: {
            next_review: "2026-05-11",
            monitoring: true,
            monitoring_detail: "Gate re-evaluated on every pipeline run.",
            triggers: [
                "Critical POA&M item resolved (POAM-001 or POAM-002)",
                "Override approved or expired",
                "Remediation PR merged and pipeline re-run"
            ]
        }
    }
};

var SAMPLE_POAM = {
    items: [
        { id: "POAM-001", finding: "SQL Injection in /api/v1/payments", severity: "critical", scanner: "Semgrep", control: "PCI-DSS-6.2.4", deadline: "2026-05-11T00:00:00Z", status: "open", responsible: "Backend Team", threat_event: "TE-001", assets: ["AST-001", "AST-003"], remediation: { plan: "Refactor payment service to use ORM-only data access pattern. All raw SQL queries must be replaced with parameterized ORM methods.", milestones: [ { step: "Identify all raw SQL queries in payment module", target: "2026-05-06", status: "completed" }, { step: "Replace with SQLAlchemy ORM queries", target: "2026-05-08", status: "in-progress" }, { step: "Add parameterized query unit tests", target: "2026-05-09", status: "open" }, { step: "Deploy WAF SQLi ruleset", target: "2026-05-10", status: "open" }, { step: "Verify with Semgrep + ZAP rescan", target: "2026-05-11", status: "open" } ], cost_estimate: "high", risk_if_delayed: "Direct PCI cardholder data exposure. PCI DSS non-compliance triggering Level 1 assessment." } },
        { id: "POAM-002", finding: "Hardcoded API key in Docker layer", severity: "high", scanner: "Gitleaks", control: "ASVS-V2.5.4", deadline: "2026-05-08T00:00:00Z", status: "in-progress", responsible: "DevOps", threat_event: "TE-002", assets: ["AST-004"], remediation: { plan: "Rotate all exposed credentials. Implement multi-stage Docker build with secret mounting via BuildKit.", milestones: [ { step: "Rotate exposed API key and DB connection string", target: "2026-05-05", status: "completed" }, { step: "Refactor Dockerfile to multi-stage build", target: "2026-05-06", status: "completed" }, { step: "Add BuildKit secret mount for credentials", target: "2026-05-07", status: "in-progress" }, { step: "Verify no secrets in image layers (Gitleaks rescan)", target: "2026-05-08", status: "open" } ], cost_estimate: "moderate", risk_if_delayed: "Lateral movement to database tier via compromised credentials." } },
        { id: "POAM-003", finding: "Overly permissive IAM role (s3:*)", severity: "high", scanner: "Checkov", control: "PCI-DSS-7.2.2", deadline: "2026-05-14T00:00:00Z", status: "open", responsible: "Cloud Infra", threat_event: "TE-003", assets: ["AST-002", "AST-005"], remediation: { plan: "Apply least-privilege IAM policy scoped to specific S3 bucket ARNs with read-only actions for the payment-api execution role.", milestones: [ { step: "Audit current IAM policy usage with Access Analyzer", target: "2026-05-07", status: "open" }, { step: "Draft scoped IAM policy (specific ARNs + actions)", target: "2026-05-09", status: "open" }, { step: "Deploy to staging and verify payment flow", target: "2026-05-11", status: "open" }, { step: "Enable S3 access logging", target: "2026-05-12", status: "open" }, { step: "Verify with Checkov rescan", target: "2026-05-14", status: "open" } ], cost_estimate: "moderate", risk_if_delayed: "Full S3 data exfiltration. APPI/GDPR notification required on breach." } },
        { id: "POAM-004", finding: "CVE-2026-0778 OpenSSL buffer overflow", severity: "high", scanner: "Grype", control: "PCI-DSS-6.3.1", deadline: "2026-05-10T00:00:00Z", status: "in-progress", responsible: "DevOps", threat_event: "TE-004", assets: ["AST-001"], remediation: { plan: "Update base image to python:3.11-slim-bookworm which includes OpenSSL 3.1.5 (patched).", milestones: [ { step: "Test python:3.11-slim-bookworm compatibility", target: "2026-05-06", status: "completed" }, { step: "Update Dockerfile base image", target: "2026-05-07", status: "completed" }, { step: "Rebuild and scan container image", target: "2026-05-08", status: "in-progress" }, { step: "Deploy to staging", target: "2026-05-09", status: "open" }, { step: "Verify CVE resolved with Grype rescan", target: "2026-05-10", status: "open" } ], cost_estimate: "low", risk_if_delayed: "Remote code execution within container. EPSS 0.42 indicates moderate active exploitation." } },
        { id: "POAM-005", finding: "Missing mTLS on service mesh", severity: "medium", scanner: "Semgrep", control: "PCI-DSS-4.2.1", deadline: "2026-05-21T00:00:00Z", status: "open", responsible: "Platform Team", threat_event: "TE-005", assets: ["AST-003", "AST-005"], remediation: { plan: "Enable Istio strict mTLS mode for all inter-service communication in the payment namespace.", milestones: [ { step: "Audit current service mesh traffic (encrypted vs plain)", target: "2026-05-12", status: "open" }, { step: "Enable Istio permissive mTLS (monitoring mode)", target: "2026-05-15", status: "open" }, { step: "Switch to strict mTLS after validation", target: "2026-05-19", status: "open" }, { step: "Verify all traffic encrypted", target: "2026-05-21", status: "open" } ], cost_estimate: "moderate", risk_if_delayed: "Interception of payment tokens and fraud scoring data in transit." } },
        { id: "POAM-006", finding: "Unrestricted S3 bucket policy", severity: "high", scanner: "Checkov", control: "PCI-DSS-7.2.1", deadline: "2026-05-12T00:00:00Z", status: "open", responsible: "Cloud Infra", threat_event: "TE-003", assets: ["AST-002"], remediation: { plan: "Restrict S3 bucket policy to VPC endpoint access only. Add bucket-level encryption enforcement.", milestones: [ { step: "Add VPC endpoint condition to bucket policy", target: "2026-05-08", status: "open" }, { step: "Enable SSE-S3 default encryption", target: "2026-05-10", status: "open" }, { step: "Verify with Checkov rescan", target: "2026-05-12", status: "open" } ], cost_estimate: "low", risk_if_delayed: "S3 bucket accessible from any network path within the AWS account." } },
        { id: "POAM-007", finding: "Weak password hashing (MD5)", severity: "medium", scanner: "Semgrep", control: "ASVS-V2.4.1", deadline: "2026-05-18T00:00:00Z", status: "open", responsible: "Backend Team", threat_event: null, assets: ["AST-001"], remediation: { plan: "Replace MD5 password hashing with bcrypt (cost factor 12).", milestones: [ { step: "Implement bcrypt hashing in auth module", target: "2026-05-14", status: "open" }, { step: "Add migration for existing password hashes", target: "2026-05-16", status: "open" }, { step: "Verify with Semgrep rescan", target: "2026-05-18", status: "open" } ], cost_estimate: "low", risk_if_delayed: "Offline password cracking if database is compromised." } },
        { id: "POAM-008", finding: "Missing CSP headers", severity: "medium", scanner: "ZAP", control: "ASVS-V14.4.3", deadline: "2026-05-20T00:00:00Z", status: "open", responsible: "Frontend Team", threat_event: null, assets: ["AST-003"], remediation: { plan: "Add Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options headers to all API responses.", milestones: [ { step: "Add security headers middleware", target: "2026-05-16", status: "open" }, { step: "Test with ZAP rescan", target: "2026-05-18", status: "open" }, { step: "Deploy to production", target: "2026-05-20", status: "open" } ], cost_estimate: "low", risk_if_delayed: "XSS and clickjacking attacks possible." } },
        { id: "POAM-009", finding: "Unencrypted secrets in env vars", severity: "medium", scanner: "Gitleaks", control: "PCI-DSS-6.3.2", deadline: "2026-05-15T00:00:00Z", status: "in-progress", responsible: "DevOps", threat_event: "TE-002", assets: ["AST-004"], remediation: { plan: "Migrate all secrets from environment variables to AWS Secrets Manager with automatic rotation.", milestones: [ { step: "Inventory all env var secrets", target: "2026-05-08", status: "completed" }, { step: "Create Secrets Manager entries", target: "2026-05-10", status: "in-progress" }, { step: "Update application to read from Secrets Manager", target: "2026-05-13", status: "open" }, { step: "Remove env var secrets and verify", target: "2026-05-15", status: "open" } ], cost_estimate: "moderate", risk_if_delayed: "Secrets visible in container inspection and CloudWatch logs." } },
        { id: "POAM-010", finding: "Missing rate limiting on auth endpoint", severity: "medium", scanner: "ZAP", control: "ASVS-V11.1.4", deadline: "2026-05-22T00:00:00Z", status: "open", responsible: "Backend Team", threat_event: null, assets: ["AST-003"], remediation: { plan: "Implement rate limiting on /api/login endpoint (10 requests/minute per IP).", milestones: [ { step: "Add rate limiting middleware", target: "2026-05-18", status: "open" }, { step: "Configure API Gateway throttling", target: "2026-05-20", status: "open" }, { step: "Test with ZAP brute-force scan", target: "2026-05-22", status: "open" } ], cost_estimate: "low", risk_if_delayed: "Credential brute-force attacks on authentication endpoint." } },
        { id: "POAM-011", finding: "Outdated npm dependencies (3 CVEs)", severity: "low", scanner: "Grype", control: "ASVS-V14.2.1", deadline: "2026-05-25T00:00:00Z", status: "open", responsible: "Frontend Team", threat_event: null, assets: ["AST-001"], remediation: { plan: "Update all npm dependencies to latest patched versions.", milestones: [ { step: "Run npm audit and identify updates", target: "2026-05-20", status: "open" }, { step: "Update and test", target: "2026-05-23", status: "open" }, { step: "Verify with Grype rescan", target: "2026-05-25", status: "open" } ], cost_estimate: "low", risk_if_delayed: "Known vulnerabilities in client-side dependencies." } },
        { id: "POAM-012", finding: "Missing audit logging for admin actions", severity: "low", scanner: "Checkov", control: "PCI-DSS-10.2.1", deadline: "2026-05-28T00:00:00Z", status: "open", responsible: "Backend Team", threat_event: null, assets: ["AST-001", "AST-002"], remediation: { plan: "Implement structured audit logging for all admin actions using CloudWatch Logs.", milestones: [ { step: "Define audit log schema", target: "2026-05-22", status: "open" }, { step: "Implement audit middleware", target: "2026-05-25", status: "open" }, { step: "Configure CloudWatch log group + retention", target: "2026-05-27", status: "open" }, { step: "Verify audit trail completeness", target: "2026-05-28", status: "open" } ], cost_estimate: "moderate", risk_if_delayed: "No audit trail for forensic investigation after security incident." } }
    ]
};

var SAMPLE_TIMELINE = {
    runs: [
        { timestamp: "2026-04-20T10:00:00Z", gate: "DATO", risk_score: 9, findings: 28, critical: 3, high: 10, satisfied_pct: 22 },
        { timestamp: "2026-04-22T10:00:00Z", gate: "DATO", risk_score: 8, findings: 25, critical: 2, high: 9, satisfied_pct: 25 },
        { timestamp: "2026-04-24T14:30:00Z", gate: "DATO", risk_score: 8, findings: 24, critical: 2, high: 8, satisfied_pct: 28 },
        { timestamp: "2026-04-26T09:15:00Z", gate: "DATO", risk_score: 7, findings: 23, critical: 1, high: 8, satisfied_pct: 30 },
        { timestamp: "2026-04-28T11:00:00Z", gate: "DATO", risk_score: 7, findings: 22, critical: 1, high: 7, satisfied_pct: 32 },
        { timestamp: "2026-04-30T10:00:00Z", gate: "DATO", risk_score: 6, findings: 22, critical: 1, high: 7, satisfied_pct: 34 },
        { timestamp: "2026-05-02T09:00:00Z", gate: "DATO", risk_score: 6, findings: 22, critical: 1, high: 7, satisfied_pct: 36 },
        { timestamp: "2026-05-04T09:32:00Z", gate: "DATO", risk_score: 5, findings: 22, critical: 1, high: 7, satisfied_pct: 37 }
    ]
};

// ---- Constants ----

var PHASE_ORDER = ["develop", "build", "test", "decision"];
var FULL_PHASE_ORDER = ["plan", "develop", "build", "test", "release", "decision", "deploy", "monitor"];
var PLACEHOLDER_PHASES = {
    plan: "Plan phase risk assessment is conducted during sprint planning. Activities include threat modeling, architecture review, and Mission-Based Cyber Risk Assessment (MbCRA) based on system design and requirements. Tools: threat modeling tool, team collaboration system.",
    release: "Release phase includes SBOM composition analysis, release go/no-go decision based on cumulative risk assessment, and final compliance verification before artifacts are delivered to production.",
    deploy: "Deploy phase includes post-deployment security scan, infrastructure provisioning verification, and configuration drift detection. Risk assessment confirms deployment matches approved security posture.",
    monitor: "Monitor phase includes continuous compliance monitoring, runtime application security, SIEM integration, database security auditing, and ongoing MbCRA updates based on new threat intelligence."
};
var PHASE_SNAPSHOTS = {
    develop: { posture: "moderate", confidence: 40, label: "MODERATE" },
    build: { posture: "high", confidence: 65, label: "HIGH" },
    test: { posture: "high", confidence: 90, label: "HIGH" },
    decision: { posture: "high", confidence: 92, label: "DATO" }
};

// ---- State ----

var currentView = "overview";
var currentProjectId = null;
var cachedIndexData = null;
var cachedProject = null;
var cachedRiskAssessment = null;
var cachedCompliance = null;
var cachedPOAM = null;

// ---- Utility Functions ----

function formatTimestamp(iso) {
    try {
        var d = new Date(iso);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) +
            ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch (_e) {
        return iso;
    }
}

function formatDuration(ms) {
    if (ms === 0) return '--';
    if (ms < 1000) return ms + 'ms';
    var secs = (ms / 1000).toFixed(1);
    if (secs >= 60) {
        var mins = Math.floor(secs / 60);
        var remainSecs = (secs % 60).toFixed(0);
        return mins + 'm ' + remainSecs + 's';
    }
    return secs + 's';
}

function daysUntil(iso) {
    var now = new Date();
    var target = new Date(iso);
    return Math.ceil((target - now) / (1000 * 60 * 60 * 24));
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

async function fetchJSON(path) {
    try {
        var resp = await fetch(path);
        if (!resp.ok) throw new Error(resp.status);
        return await resp.json();
    } catch (_e) {
        return null;
    }
}

// Transform exporter output to dashboard expected format
function transformIndexData(raw) {
    if (!raw || raw.metadata) return raw; // Already in dashboard format
    return {
        metadata: {
            timestamp: raw.generated_at || '',
            system: raw.product || '',
            mode: raw.mode || 'static',
            version: '1.0.0'
        },
        gate: raw.gate || {},
        risk_posture: raw.risk_posture || {},
        sar_summary: raw.sar_summary || {},
        poam_summary: raw.poam_summary || {},
        pipeline: SAMPLE_INDEX.pipeline // Use sample pipeline phases — exporter doesn't produce phase structure
    };
}

function transformSP80030(raw) {
    if (!raw || raw.cross_signal_insights) return raw; // Already in dashboard format

    // Merge parallel arrays into nested threat event objects
    var sources = raw.threat_sources || [];
    var events = raw.threat_events || [];
    var likelihoods = raw.likelihood_assessments || [];
    var impacts = raw.impact_assessments || [];
    var determinations = raw.risk_determinations || [];
    var responses = raw.risk_responses || [];

    // Build source lookup by ID
    var sourceMap = {};
    sources.forEach(function(s) { sourceMap[s.id] = s; });

    // Build determination lookup by threat_event_id
    var rdMap = {};
    determinations.forEach(function(rd) { rdMap[rd.threat_event_id] = rd; });

    // Build response lookup by risk_determination_id
    var rrMap = {};
    responses.forEach(function(rr) { rrMap[rr.risk_determination_id] = rr; });

    var te = events.map(function(evt, i) {
        var ts = sourceMap[evt.source_id] || sources[i] || {};
        var lk = likelihoods[i] || {};
        var imp = impacts[i] || {};
        var rd = rdMap[evt.id] || determinations[i] || {};
        var rr = rrMap[evt.id] || responses[i] || {};

        // Clean CIA values (AI produces "HIGH — explanation", extract just the level)
        var cia = imp.cia_impact || {};
        var cleanCia = {};
        ['confidentiality','integrity','availability'].forEach(function(k) {
            var val = cia[k] || '';
            cleanCia[k] = val.split(' ')[0].toLowerCase().replace(/[^a-z]/g,'') || 'moderate';
        });

        // Truncate title from long description
        var title = evt.description || '';
        if (title.length > 80) title = title.substring(0, title.indexOf('.') > 0 ? title.indexOf('.') : 80);

        return {
            id: evt.id,
            title: title,
            threat_source: { type: ts.type || 'adversarial', name: ts.name || '', capability: ts.capability || '', intent: ts.intent || '', targeting: ts.targeting || '' },
            mitre_technique: evt.mitre_technique || '',
            mitre_name: '',
            risk_level: rd.risk_level || 'moderate',
            relevance: evt.relevance || 'confirmed',
            likelihood: { initiation: lk.initiation_likelihood || '', impact: lk.impact_likelihood || '', overall: lk.overall_likelihood || '', epss: lk.epss_score || null, evidence: lk.evidence || '' },
            impact: { severity: imp.severity || 'moderate', impact_type: imp.impact_type || '', cia: cleanCia, business: imp.business_impact || '' },
            risk_score: rd.risk_score || 50,
            vulnerabilities: [],
            predisposing_conditions: lk.predisposing_conditions || [],
            uncertainty: 'moderate',
            sources: [],
            response: { type: rr.response_type || 'mitigate', description: rr.description || '', deadline: rr.deadline || '', milestones: rr.milestones || [] },
            controls: (imp.compliance_impact || []),
            narrative: evt.description || '',
            discovered_at: i < 2 ? 'develop' : (i < 4 ? 'build' : 'test'),
            confirmed_at: null
        };
    });

    return {
        prepare: SAMPLE_RISK_ASSESSMENT.prepare,
        executive_summary: raw.executive_summary || '',
        cross_signal_insights: raw.recommendations || [],
        overall_risk_posture: te.length > 0 ? te[0].risk_level : 'moderate',
        threat_events: te,
        appendix: SAMPLE_RISK_ASSESSMENT.appendix
    };
}

function transformSAR(raw) {
    if (!raw || (raw.frameworks)) return raw; // Already in dashboard format
    // Group control_assessments by framework
    var fwMap = {};
    (raw.control_assessments || []).forEach(function(ca) {
        var fw = ca.framework || 'unknown';
        if (!fwMap[fw]) fwMap[fw] = { id: fw, name: fw.replace(/-/g,' ').replace(/\b\w/g, function(c){return c.toUpperCase();}), satisfied: 0, total: 0, controls: [] };
        fwMap[fw].total++;
        if (ca.status === 'satisfied') fwMap[fw].satisfied++;
        var findings = [];
        if (ca.status === 'other-than-satisfied' && ca.findings_count > 0) {
            findings.push({ severity: ca.risk_level || 'medium', scanner: ca.assessor || '', message: ca.findings_summary || '', override: null });
        }
        fwMap[fw].controls.push({ id: ca.control_id, title: ca.title, status: ca.status, findings: findings });
    });
    return { frameworks: Object.values(fwMap) };
}

function transformPOAM(raw) {
    if (!raw) return raw;
    // Exporter produces { items: [...], total: N }
    // Dashboard expects same structure — just ensure items have expected fields
    var items = (raw.items || []).map(function(item) {
        return {
            id: item.id || '',
            finding: item.weakness || item.finding || '',
            severity: item.severity || 'medium',
            scanner: item.source || item.scanner || '',
            control: item.control_id || item.control || '',
            deadline: item.scheduled_completion || item.deadline || '',
            status: item.status || 'open',
            responsible: item.responsible || '',
            threat_event: null,
            assets: [],
            remediation: {
                plan: item.weakness || '',
                milestones: (item.milestones || []).map(function(m) {
                    return { step: m.description || '', target: m.target_date || '', status: m.status || 'open' };
                }),
                cost_estimate: item.cost_estimate || 'moderate',
                risk_if_delayed: ''
            }
        };
    });
    return { items: items };
}

function getBreakdownColor(key) {
    var colors = {
        critical: 'var(--danger)',
        'very-high': 'var(--danger)',
        high: 'var(--warning)',
        medium: 'var(--info)',
        moderate: 'var(--info)',
        low: 'var(--success)',
        'very-low': 'var(--text-3)',
        enriched: 'var(--info)',
        total_cves: 'var(--text-2)',
        violations: 'var(--danger)',
        informational: 'var(--text-3)'
    };
    return colors[key] || 'var(--text-3)';
}

function getGateBadgeClass(decision) {
    var d = (decision || '').toUpperCase();
    if (d === 'ATO') return 'ato';
    if (d === 'ATO-WITH-CONDITIONS' || d === 'ATO WITH CONDITIONS') return 'ato-conditions';
    return 'dato';
}

function sortControls(controls) {
    var order = { 'other-than-satisfied': 0, 'not-assessed': 1, 'satisfied': 2 };
    return controls.slice().sort(function(a, b) {
        var oa = order[a.status] !== undefined ? order[a.status] : 1;
        var ob = order[b.status] !== undefined ? order[b.status] : 1;
        return oa - ob;
    });
}

function getPhaseFindings(phase) {
    var total = 0;
    (phase.steps || []).forEach(function(s) {
        if (s.id !== 'epss' && s.id !== 'gate') total += s.findings;
    });
    return total;
}

function getFindingCountClass(n) {
    if (n === 0) return 'count-zero';
    if (n <= 3) return 'count-low';
    return 'count-high';
}

function getStepFindingClass(n) {
    if (n === 0) return 'f-zero';
    if (n <= 3) return 'f-low';
    return 'f-high';
}

// ---- Phase-to-Threat Mapping ----

function getThreatsAtPhase(phase) {
    var phaseIdx = PHASE_ORDER.indexOf(phase);
    return (cachedRiskAssessment || SAMPLE_RISK_ASSESSMENT).threat_events.filter(function(te) {
        var discoveredIdx = PHASE_ORDER.indexOf(te.discovered_at);
        return discoveredIdx <= phaseIdx;
    }).map(function(te) {
        var status = "unchanged";
        if (te.discovered_at === phase) status = "new";
        else if (te.confirmed_at === phase) status = "updated";
        return Object.assign({}, te, { phase_status: status });
    });
}

function getAssetsAtPhase(phase) {
    var threats = getThreatsAtPhase(phase);
    var teIds = {};
    threats.forEach(function(t) { teIds[t.id] = true; });
    return SAMPLE_ASSETS.filter(function(a) {
        return a.threat_events.some(function(te) { return teIds[te]; });
    }).map(function(a) {
        var relevantTEs = a.threat_events.filter(function(te) { return teIds[te]; });
        return Object.assign({}, a, { relevant_threats: relevantTEs });
    });
}

// ---- Router ----

function getRoute() {
    var hash = window.location.hash || '#/';
    if (hash === '#' || hash === '') hash = '#/';

    var match = hash.match(/^#\/projects\/(.+)$/);
    if (match) {
        return { view: 'detail', projectId: decodeURIComponent(match[1]) };
    }

    return { view: 'list' };
}

function navigateTo(hash) {
    window.location.hash = hash;
}

// ---- Shared Header ----

function renderListHeader() {
    return '' +
        '<header class="site-header">' +
            '<div class="header-left">' +
                '<h1 class="site-title" tabindex="0" role="link">Security Dashboard</h1>' +
            '</div>' +
            '<div class="header-right">' +
                '<div class="footer-links">' +
                    '<a href="https://github.com/s1ns3nz0/ai-devsecops" target="_blank" rel="noopener noreferrer">GitHub</a>' +
                '</div>' +
            '</div>' +
        '</header>';
}

function renderDetailHeader(meta, gate, project) {
    var gateClass = getGateBadgeClass(gate.decision);
    return '' +
        '<header class="site-header">' +
            '<div class="detail-header-bar">' +
                '<button class="back-btn" id="back-btn" tabindex="0">' +
                    '<svg viewBox="0 0 16 16" fill="none"><path d="M10 3L5 8l5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
                    'Back to projects' +
                '</button>' +
                '<span class="detail-name">' + escapeHtml(meta.system || '') + '</span>' +
                '<span class="gate-badge-inline ' + gateClass + '">' + escapeHtml(gate.decision || '---') + '</span>' +
                '<span class="detail-timestamp">' + formatTimestamp(meta.timestamp) + '</span>' +
            '</div>' +
            '<div class="header-right">' +
                '<div class="footer-links">' +
                    '<a href="https://github.com/s1ns3nz0/ai-devsecops" target="_blank" rel="noopener noreferrer">GitHub</a>' +
                '</div>' +
            '</div>' +
        '</header>';
}

// ---- Project List View (UNCHANGED) ----

function renderProjectListView(projects) {
    var html = '<div class="view-enter">';
    html += '<div class="section" style="margin-top:24px"><h2 class="section-title">Projects</h2></div>';
    html += '<div class="project-list">';

    projects.forEach(function(p) {
        var gateClass = getGateBadgeClass(p.gate);
        var ts = formatTimestamp(p.last_scan);
        var fs = p.findings_summary || {};

        var findingsHtml = '';
        if (fs.critical) findingsHtml += '<span class="f-critical">' + fs.critical + ' cr</span>';
        if (fs.high) findingsHtml += '<span class="f-high">' + fs.high + ' high</span>';
        if (fs.medium) findingsHtml += '<span class="f-medium">' + fs.medium + ' med</span>';
        if (fs.low) findingsHtml += '<span class="f-low">' + fs.low + ' low</span>';

        var tagsHtml = '';
        (p.frameworks || []).forEach(function(fw) {
            tagsHtml += '<span class="pill pill-framework">' + escapeHtml(fw) + '</span>';
        });
        (p.data_classification || []).forEach(function(dc) {
            tagsHtml += '<span class="pill pill-data">' + escapeHtml(dc) + '</span>';
        });

        html +=
            '<a class="project-card" href="#/projects/' + encodeURIComponent(p.id) + '" role="listitem" tabindex="0">' +
                '<div class="project-info">' +
                    '<div class="project-name">' + escapeHtml(p.name) + '</div>' +
                    '<div class="project-repo">' + escapeHtml(p.repo_url || p.repo || '') + '</div>' +
                    '<div class="project-tags">' + tagsHtml + '</div>' +
                '</div>' +
                '<div class="project-right">' +
                    '<span class="gate-badge-inline ' + gateClass + '">' + escapeHtml(p.gate) + '</span>' +
                    '<span class="project-timestamp">' + ts + '</span>' +
                    '<div class="project-findings-summary">' + findingsHtml + '</div>' +
                '</div>' +
            '</a>';
    });

    html += '</div></div>';
    return html;
}

// ---- Left Panel ----

function renderLeftPanel(indexData) {
    var pipeline = indexData.pipeline || {};
    var phases = pipeline.phases || [];
    var gate = indexData.gate || {};

    var html = '';

    // Pipeline section
    html += '<div class="nav-group-label">PIPELINE</div>';

    // Build a lookup of implemented phases
    var phaseDataMap = {};
    phases.forEach(function(p) { phaseDataMap[p.name.toLowerCase()] = p; });

    // Render all phases in full DoD order
    FULL_PHASE_ORDER.forEach(function(phaseName) {
        var phase = phaseDataMap[phaseName];
        var isPlaceholder = !phase;
        var activeClass = (currentView === phaseName) ? ' active' : '';
        var disabledClass = isPlaceholder ? ' disabled' : '';

        if (isPlaceholder) {
            // Placeholder phase (plan, release, deploy, monitor)
            html +=
                '<div class="nav-phase' + activeClass + disabledClass + '" data-phase="' + phaseName + '">' +
                    '<span class="nav-phase-dot" style="background:var(--text-3);opacity:0.4"></span>' +
                    '<span class="nav-phase-name">' + escapeHtml(phaseName.toUpperCase()) + '</span>' +
                    '<span class="nav-phase-placeholder">\u2014</span>' +
                '</div>';
        } else {
            var phaseLower = phase.name.toLowerCase();
            var dotClass = 'completed';
            var isDecision = phaseLower === 'decision';

            // Decision phase: gate status
            if (isDecision) {
                var hasBlocked = phase.steps.some(function(s) { return s.status === 'blocked'; });
                dotClass = hasBlocked ? 'blocked' : 'completed';
            }

            // Accent phases get the "current" dot
            if (phase.accent) dotClass = 'current';

            var countHtml = '';
            if (isDecision) {
                var gateLabel = gate.decision || 'PASS';
                var gateClass = getGateBadgeClass(gateLabel);
                countHtml = '<span class="nav-phase-count count-gate ' + gateClass + '">' + escapeHtml(gateLabel) + '</span>';
            } else {
                var fc = getPhaseFindings(phase);
                countHtml = '<span class="nav-phase-count ' + getFindingCountClass(fc) + '">' + fc + '</span>';
            }

            html +=
                '<div class="nav-phase' + activeClass + '" data-phase="' + phaseLower + '">' +
                    '<span class="nav-phase-dot ' + dotClass + '"></span>' +
                    '<span class="nav-phase-name">' + escapeHtml(phase.name) + '</span>' +
                    countHtml +
                '</div>';

            // Sub-steps (shown when active)
            html += '<div class="nav-steps">';
            (phase.steps || []).forEach(function(step) {
                var fClass = getStepFindingClass(step.findings);
                html +=
                    '<div class="nav-step">' +
                        '<span class="nav-step-icon ' + step.status + '"></span>' +
                        '<span class="nav-step-name">' + escapeHtml(step.scanner) + '</span>' +
                        '<span class="nav-step-findings ' + fClass + '">' + step.findings + '</span>' +
                    '</div>';
            });
            html += '</div>';
        }
    });

    // Divider
    html += '<div class="nav-divider"></div>';

    // Sections nav
    html += '<div class="nav-group-label">SECTIONS</div>';

    var sections = [
        { id: "overview", icon: "\u25C9", label: "Overview" },
        { id: "sbom", icon: "\u25CB", label: "SBOM" },
        { id: "compliance", icon: "\u25CB", label: "Compliance" },
        { id: "poam", icon: "\u25CB", label: "Action Items" },
        { id: "timeline", icon: "\u25CB", label: "Timeline" }
    ];

    sections.forEach(function(sec) {
        var activeClass = (currentView === sec.id) ? ' active' : '';
        var icon = (currentView === sec.id) ? "\u25C9" : "\u25CB";
        html +=
            '<div class="nav-section' + activeClass + '" data-section="' + sec.id + '">' +
                '<span class="nav-section-icon">' + icon + '</span>' +
                '<span class="nav-section-name">' + escapeHtml(sec.label) + '</span>' +
            '</div>';
    });

    // Divider
    html += '<div class="nav-divider"></div>';

    // Overrides
    var overrides = SAMPLE_OVERRIDES;
    if (overrides && overrides.length > 0) {
        html += '<div class="nav-overrides">';
        html += '<div class="nav-overrides-label">OVERRIDES (' + overrides.length + ')</div>';
        overrides.forEach(function(ov) {
            var days = daysUntil(ov.expires);
            var expiryClass = 'ok';
            if (days < 7) expiryClass = 'urgent';
            else if (days < 14) expiryClass = 'warning';
            var expiryText = days < 0 ? Math.abs(days) + 'd expired' : days + 'd';

            html +=
                '<div class="nav-override-item">' +
                    '<span class="nav-override-id">' + escapeHtml(ov.finding_id) + '</span>' +
                    '<span class="nav-override-expiry ' + expiryClass + '">' + expiryText + '</span>' +
                '</div>';
        });
        html += '</div>';
    }

    return html;
}

// ---- Right Panel Content Renderers ----

function renderRightPanel(view) {
    var container = document.getElementById('right-panel');
    if (!container) return;

    container.innerHTML = '<div class="view-enter">' + getRightPanelContent(view) + '</div>';

    // Wire interactivity after rendering
    wireRightPanelInteractivity(view, container);
}

function getRightPanelContent(view) {
    if (view === 'overview') return renderOverviewContent();
    if (PHASE_ORDER.indexOf(view) !== -1) return renderPhaseContent(view);
    if (PLACEHOLDER_PHASES[view]) return renderPlaceholderPhase(view);
    if (view === 'sbom') return renderSBOMContent();
    if (view === 'compliance') return renderComplianceContent();
    if (view === 'poam') return renderPOAMContent();
    if (view === 'timeline') return renderTimelineContent();
    return '<div class="loading-placeholder"><span>Unknown view.</span></div>';
}

function renderPlaceholderPhase(phase) {
    var html = '<h2 class="section-title" style="margin-bottom:20px">' + escapeHtml(phase.toUpperCase()) + ' \u2014 Risk Assessment</h2>';
    html += '<div class="phase-exec-summary"><div class="phase-exec-label">Phase Status: Not Yet Implemented</div>';
    html += '<p>' + escapeHtml(PLACEHOLDER_PHASES[phase]) + '</p>';
    html += '</div>';
    return html;
}

// ---- Overview Content ----

function renderOverviewContent() {
    var ra = cachedRiskAssessment || SAMPLE_RISK_ASSESSMENT;
    var idx = cachedIndexData || SAMPLE_INDEX;
    var sarSum = idx.sar_summary || {};

    var html = '<h2 class="section-title" style="margin-bottom:20px">Overview</h2>';

    // --- Gap 7: Assessment Context (full, collapsible) ---
    html += '<details class="phase-context" style="margin-bottom:20px"><summary>Assessment Context (SP 800-30 Prepare)</summary>';
    html += '<div class="phase-context-body">';
    html += '<div class="ra-detail-row"><span class="ra-label">Purpose</span><span class="ra-evidence">' + escapeHtml(ra.prepare.purpose) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Tier</span><span>' + escapeHtml(ra.prepare.scope.tier) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">System</span><span>' + escapeHtml(ra.prepare.scope.system) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Boundary</span><span class="ra-evidence">' + escapeHtml(ra.prepare.scope.boundary) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Time Frame</span><span>' + escapeHtml(ra.prepare.scope.time_frame) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Applicability</span><span>' + escapeHtml(ra.prepare.scope.applicability) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Risk Model</span><span>' + escapeHtml(ra.prepare.risk_model) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Assessment Approach</span><span class="ra-evidence">' + escapeHtml(ra.prepare.assessment_approach) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Analysis Approach</span><span>' + escapeHtml(ra.prepare.analysis_approach) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Assessment Type</span><span>' + escapeHtml(ra.prepare.assessment_type) + '</span></div>';
    // Assumptions
    html += '<div style="margin-top:12px"><div class="phase-exec-label">Assumptions</div><ul class="ra-prepare-list">';
    ra.prepare.assumptions.forEach(function(a) { html += '<li>' + escapeHtml(a) + '</li>'; });
    html += '</ul></div>';
    // Constraints
    html += '<div style="margin-top:8px"><div class="phase-exec-label">Constraints</div><ul class="ra-prepare-list">';
    ra.prepare.constraints.forEach(function(c) { html += '<li>' + escapeHtml(c) + '</li>'; });
    html += '</ul></div>';
    // Information Sources table
    html += '<div style="margin-top:12px"><div class="phase-exec-label">Information Sources</div>';
    html += '<div class="table-container" style="margin-top:8px"><table class="data-table ra-sources-table"><thead><tr><th>Source</th><th>Type</th><th>Description</th></tr></thead><tbody>';
    ra.prepare.information_sources.forEach(function(src) {
        html += '<tr><td style="font-weight:600">' + escapeHtml(src.source) + '</td><td><span class="scanner-badge">' + escapeHtml(src.type) + '</span></td><td style="color:var(--text-2)">' + escapeHtml(src.description) + '</td></tr>';
    });
    html += '</tbody></table></div></div>';
    html += '</div></details>';

    // Risk Evolution
    html += '<div class="risk-evolution">';
    var evoData = [
        { phase: "DEVELOP", snap: PHASE_SNAPSHOTS.develop, delta: null },
        { phase: "BUILD", snap: PHASE_SNAPSHOTS.build, delta: "risk elevated" },
        { phase: "TEST", snap: PHASE_SNAPSHOTS.test, delta: "confidence increased" },
        { phase: "DECISION", snap: PHASE_SNAPSHOTS.decision, delta: null }
    ];

    evoData.forEach(function(row) {
        var dotClass = row.snap.posture;
        if (row.phase === "DECISION") dotClass = "dato";
        var labelClass = dotClass;

        html +=
            '<div class="risk-evo-row">' +
                '<span class="evo-phase">' + row.phase + '</span>' +
                '<span class="evo-dot ' + dotClass + '"></span>' +
                '<span class="evo-line"></span>' +
                '<span class="evo-label ' + labelClass + '">' + row.snap.label + '</span>' +
                '<span class="evo-confidence">' + row.snap.confidence + '%</span>' +
                (row.delta ? '<span class="evo-delta">\u25B2 ' + row.delta + '</span>' : '') +
            '</div>';
    });
    html += '</div>';

    // Executive Summary
    if (ra.executive_summary) {
        html +=
            '<div class="overview-exec-summary">' +
                '<h3>Executive Summary</h3>' +
                '<p>' + escapeHtml(ra.executive_summary) + '</p>' +
            '</div>';
    }

    // --- Gap 9: Cross-Signal Insights ---
    if (ra.cross_signal_insights && ra.cross_signal_insights.length > 0) {
        html += '<div class="phase-insights" style="margin-bottom:20px"><div class="phase-exec-label">Cross-Signal Insights</div>';
        ra.cross_signal_insights.forEach(function(insight) {
            html += '<div class="insight-item"><span class="insight-icon">\u26A1</span>' + escapeHtml(insight) + '</div>';
        });
        html += '</div>';
    }

    // Key Metrics
    html += '<div class="overview-metrics">';
    html += '<div class="metric-card"><div class="metric-value">6</div><div class="metric-label">Threat Events</div><div class="metric-detail">3 confirmed</div></div>';
    html += '<div class="metric-card"><div class="metric-value">5</div><div class="metric-label">Assets Affected</div></div>';
    html += '<div class="metric-card"><div class="metric-value">' + (idx.risk_posture ? idx.risk_posture.total_findings : 27) + '</div><div class="metric-label">Total Findings</div><div class="metric-detail">5 scanners</div></div>';
    html += '<div class="metric-card"><div class="metric-value">' + (sarSum.coverage_pct || 37.3) + '%</div><div class="metric-label">SAR Coverage</div><div class="metric-detail">' + (sarSum.total_controls || 102) + ' controls</div></div>';
    html += '</div>';

    // --- Gap 8: Risk Matrix (all threats, final state) ---
    html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Risk Matrix (SP 800-30 Table I-2)</h3>';
    html += renderRiskMatrix(ra.threat_events);

    // --- Gap 10: NIST Table I-5/I-7 toggle (all threats) ---
    var allAdversarial = ra.threat_events.filter(function(t) { return t.threat_source && t.threat_source.type === 'adversarial'; });
    var allNonAdversarial = ra.threat_events.filter(function(t) { return !t.threat_source || t.threat_source.type !== 'adversarial'; });
    html +=
        '<div style="margin-top:24px">' +
            '<div class="ra-view-toggle">' +
                '<button class="ra-toggle-btn active" data-view="cards">Summary</button>' +
                '<button class="ra-toggle-btn" data-view="nist-table">NIST Table I-5 / I-7</button>' +
            '</div>' +
            '<div class="ra-cards-view" style="display:none"></div>' +
            '<div class="ra-table-view" style="display:none">' +
                renderAssetRiskSummary() +
                renderNISTTableI5(allAdversarial) +
                renderNISTTableI7(allNonAdversarial) +
            '</div>' +
        '</div>';

    // --- Post-Assessment sections for Overview (DECISION phase data) ---
    var overviewStData = SAMPLE_STAKEHOLDER_ACTIONS.decision;
    if (overviewStData && overviewStData.mission_impact) {
        var omi = overviewStData.mission_impact;
        html += '<h3 class="section-title" style="margin:24px 0 12px;font-size:0.95rem">Mission Impact</h3>';
        html += '<div class="mission-impact">';
        html += '<div class="mission-row mission-row-revenue"><span class="mission-label">Revenue</span><span class="mission-text">' + escapeHtml(omi.revenue || '') + '</span></div>';
        html += '<div class="mission-row mission-row-sla"><span class="mission-label">SLA</span><span class="mission-text">' + escapeHtml(omi.sla || '') + '</span></div>';
        html += '<div class="mission-row mission-row-regulatory"><span class="mission-label">Regulatory</span><span class="mission-text">' + escapeHtml(omi.regulatory || '') + '</span></div>';
        html += '<div class="mission-row mission-row-supply"><span class="mission-label">Supply Chain</span><span class="mission-text">' + escapeHtml(omi.supply_chain || '') + '</span></div>';
        html += '</div>';
    }

    if (overviewStData && overviewStData.stakeholders && overviewStData.stakeholders.length > 0) {
        html += '<h3 class="section-title" style="margin:24px 0 12px;font-size:0.95rem">Stakeholder Communication (SP 800-30 Step 3)</h3>';
        html += '<div class="stakeholder-table"><div class="table-container"><table class="data-table">';
        html += '<thead><tr><th>Stakeholder</th><th>Key Finding</th><th>Urgency</th><th>Recommended Action</th><th>Decision Required</th></tr></thead><tbody>';
        overviewStData.stakeholders.forEach(function(sh) {
            var urgClass = (sh.urgency || 'info').toLowerCase();
            var poamTags = '';
            if (sh.poam) {
                sh.poam.split(',').forEach(function(p) {
                    poamTags += ' <span class="ra-control-tag">' + escapeHtml(p.trim()) + '</span>';
                });
            }
            html +=
                '<tr>' +
                    '<td style="font-weight:600">' + escapeHtml(sh.role) + '</td>' +
                    '<td style="font-size:0.75rem">' + escapeHtml(sh.finding) + '</td>' +
                    '<td><span class="urgency-badge ' + urgClass + '">' + escapeHtml(sh.urgency.toUpperCase()) + '</span></td>' +
                    '<td style="font-size:0.75rem">' + escapeHtml(sh.action) + poamTags + '</td>' +
                    '<td style="font-size:0.75rem;color:var(--text-2);font-style:italic">' + (sh.decision ? escapeHtml(sh.decision) : '\u2014') + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div></div>';
    }

    if (overviewStData && overviewStData.reassessment) {
        var oReassess = overviewStData.reassessment;
        html += '<h3 class="section-title" style="margin:24px 0 12px;font-size:0.95rem">Reassessment &amp; Monitoring (SP 800-30 Step 4)</h3>';
        html += '<div class="reassessment-card">';
        html += '<div class="reassessment-meta">';
        html += '<span class="reassessment-item"><span class="ra-label">Next Review</span><span>' + escapeHtml(oReassess.next_review || '') + '</span></span>';
        var oMonBadge = oReassess.monitoring ? '<span class="monitoring-badge active">Active</span>' : '<span class="monitoring-badge inactive">Inactive</span>';
        html += '<span class="reassessment-item"><span class="ra-label">Monitoring</span>' + oMonBadge + ' ' + escapeHtml(oReassess.monitoring_detail || '') + '</span>';
        html += '</div>';
        if (oReassess.triggers && oReassess.triggers.length > 0) {
            html += '<div class="reassessment-triggers">';
            html += '<div class="phase-exec-label">Triggers for Reassessment</div>';
            html += '<ul class="ra-prepare-list">';
            oReassess.triggers.forEach(function(t) { html += '<li>' + escapeHtml(t) + '</li>'; });
            html += '</ul></div>';
        }
        html += '</div>';
    }

    // --- Gap 11: Appendix (collapsible) ---
    if (ra.appendix) {
        html += '<details class="phase-context" style="margin-top:24px"><summary>Appendix</summary>';
        html += '<div class="phase-context-body">';
        html += '<div class="ra-detail-row"><span class="ra-label">Methodology</span><span>' + escapeHtml(ra.appendix.methodology_reference) + '</span></div>';
        // Assessment Team
        html += '<div style="margin-top:12px"><div class="phase-exec-label">Assessment Team</div>';
        html += '<div class="table-container" style="margin-top:8px"><table class="data-table ra-sources-table"><thead><tr><th>Role</th><th>Name</th></tr></thead><tbody>';
        ra.appendix.assessment_team.forEach(function(member) {
            html += '<tr><td style="color:var(--text-2)">' + escapeHtml(member.role) + '</td><td style="font-weight:600">' + escapeHtml(member.name) + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
        // Related Documents
        html += '<div style="margin-top:12px"><div class="phase-exec-label">Related Documents</div><ul class="ra-prepare-list">';
        ra.appendix.related_documents.forEach(function(doc) { html += '<li>' + escapeHtml(doc) + '</li>'; });
        html += '</ul></div>';
        html += '</div></details>';
    }

    return html;
}

// ---- Risk Matrix (SP 800-30 Table I-2) ----

function renderRiskMatrix(threats) {
    var levels = ['very-high', 'high', 'moderate', 'low', 'very-low'];
    var labels = ['VH', 'H', 'M', 'L', 'VL'];
    var matrix = [
        ['very-low','low','moderate','high','very-high'],
        ['very-low','low','moderate','high','very-high'],
        ['very-low','low','moderate','moderate','high'],
        ['very-low','low','low','low','moderate'],
        ['very-low','very-low','very-low','low','low']
    ];

    // Map threats to cells
    var cellThreats = {};
    threats.forEach(function(te) {
        var lk = levels.indexOf(te.likelihood.overall);
        var imp = levels.indexOf((te.impact || {}).severity || 'moderate');
        var key = lk + ',' + imp;
        if (!cellThreats[key]) cellThreats[key] = [];
        cellThreats[key].push(te.id);
    });

    var html = '<div class="risk-matrix-compact"><table class="rm-table"><thead><tr><th></th>';
    labels.forEach(function(l) { html += '<th class="rm-header">' + l + '</th>'; });
    html += '</tr></thead><tbody>';

    for (var r = 0; r < 5; r++) {
        html += '<tr><td class="rm-row-label">' + labels[r] + '</td>';
        for (var c = 0; c < 5; c++) {
            var level = matrix[r][c];
            var key = r + ',' + c;
            var dots = cellThreats[key] || [];
            html += '<td class="rm-cell rm-' + level.replace(' ','-') + '">';
            if (dots.length > 0) {
                html += '<div class="rm-dots">';
                dots.forEach(function(id) { html += '<span class="rm-dot">' + id + '</span>'; });
                html += '</div>';
            }
            html += '</td>';
        }
        html += '</tr>';
    }

    html += '</tbody></table>';
    html += '<div style="display:flex;justify-content:space-between;font-size:0.6rem;color:var(--text-3);margin-top:4px;padding:0 40px"><span>\u2190 Impact \u2192</span><span>SP 800-30 Table I-2</span></div>';
    html += '</div>';
    return html;
}

// ---- Phase Content ----

function renderPhaseContent(phase) {
    var idx = cachedIndexData || SAMPLE_INDEX;
    var pipeline = idx.pipeline || {};
    var phases = pipeline.phases || [];
    var phaseData = null;
    for (var i = 0; i < phases.length; i++) {
        if (phases[i].name.toLowerCase() === phase) { phaseData = phases[i]; break; }
    }
    if (!phaseData) return '<div class="loading-placeholder"><span>Phase not found.</span></div>';

    var snap = phaseData.risk_snapshot || {};
    var postureClass = (snap.posture || 'moderate').replace(' ', '-');

    var html = '<h2 class="section-title" style="margin-bottom:20px">' + escapeHtml(phaseData.name) + ' \u2014 Risk Assessment</h2>';

    // Risk snapshot bar
    var newText = snap.new_threats > 0 ? ', +' + snap.new_threats + ' new' : '';
    html +=
        '<div class="phase-risk-bar">' +
            '<span class="risk-posture ' + postureClass + '">' + (snap.posture || 'UNKNOWN').toUpperCase() + '</span>' +
            '<div class="confidence-bar-track"><div class="confidence-bar-fill" style="width:' + (snap.confidence || 0) + '%"></div></div>' +
            '<span style="font-size:0.75rem;color:var(--text-2);font-family:var(--mono)">Confidence: ' + (snap.confidence || 0) + '%</span>' +
            '<span class="phase-stats">' + (snap.threats_identified || 0) + ' threats, ' + (snap.confirmed || 0) + ' confirmed' + newText + '</span>' +
        '</div>';

    // --- Gap 3: Phase Assessment Summary (narrative) ---
    if (snap.note) {
        html += '<div class="phase-exec-summary"><div class="phase-exec-label">Phase Assessment Summary</div><p>' + escapeHtml(snap.note) + '</p></div>';
    }

    // Scanners
    html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Scanners</h3>';
    html += '<div class="phase-scanners">';
    html += renderPipelineSteps(phaseData.steps || []);
    html += '</div>';

    // --- Gap 6: Separate adversarial / non-adversarial threat events ---
    var threats = getThreatsAtPhase(phase);
    var advThreats = threats.filter(function(t) { return !t.threat_source || t.threat_source.type === 'adversarial'; });
    var nonAdvThreats = threats.filter(function(t) { return t.threat_source && t.threat_source.type !== 'adversarial'; });

    html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Threat Events (' + threats.length + ')</h3>';

    if (advThreats.length > 0) {
        html += '<div style="font-size:0.7rem;font-weight:700;color:var(--text-3);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px">Adversarial (' + advThreats.length + ')</div>';
    }
    html += '<div class="phase-threats">';
    advThreats.forEach(function(te) {
        var statusBadge = '';
        if (te.phase_status === 'new') {
            statusBadge = '<span class="threat-status-badge new">NEW</span>';
        } else if (te.phase_status === 'updated') {
            statusBadge = '<span class="threat-status-badge updated">UPDATED</span>';
        } else {
            statusBadge = '<span class="threat-status-badge unchanged">from ' + (te.discovered_at || '').toUpperCase() + '</span>';
        }

        var originText = '';
        if (te.phase_status === 'unchanged') {
            originText = 'from ' + (te.discovered_at || '').toUpperCase();
            if (te.confirmed_at && PHASE_ORDER.indexOf(te.confirmed_at) <= PHASE_ORDER.indexOf(phase)) {
                originText += ', confirmed at ' + te.confirmed_at.toUpperCase();
            }
        }

        var riskClass = (te.risk_level || 'moderate').replace(' ', '-');

        html +=
            '<div class="threat-row ' + te.phase_status + '" data-te-id="' + te.id + '" role="button" tabindex="0" aria-expanded="false">' +
                statusBadge +
                '<span class="threat-row-id">' + escapeHtml(te.id) + '</span>' +
                '<span class="sev-pill ' + riskClass + '">' + (te.risk_level || '').toUpperCase() + '</span>' +
                '<span class="threat-row-title">' + escapeHtml(te.title) + '</span>' +
                (originText ? '<span class="threat-row-origin">' + escapeHtml(originText) + '</span>' : '') +
            '</div>';

        // Expandable detail
        html += '<div class="threat-detail">' + renderThreatEventDetail(te) + '</div>';
    });
    html += '</div>';

    // Non-adversarial threats
    if (nonAdvThreats.length > 0) {
        html += '<div style="font-size:0.7rem;font-weight:700;color:var(--text-3);letter-spacing:0.05em;text-transform:uppercase;margin:16px 0 8px">Non-Adversarial (' + nonAdvThreats.length + ')</div>';
        html += '<div class="phase-threats">';
        nonAdvThreats.forEach(function(te) {
            var statusBadge = '';
            if (te.phase_status === 'new') {
                statusBadge = '<span class="threat-status-badge new">NEW</span>';
            } else if (te.phase_status === 'updated') {
                statusBadge = '<span class="threat-status-badge updated">UPDATED</span>';
            } else {
                statusBadge = '<span class="threat-status-badge unchanged">from ' + (te.discovered_at || '').toUpperCase() + '</span>';
            }
            var originText = '';
            if (te.phase_status === 'unchanged') {
                originText = 'from ' + (te.discovered_at || '').toUpperCase();
            }
            var riskClass = (te.risk_level || 'moderate').replace(' ', '-');
            html +=
                '<div class="threat-row ' + te.phase_status + '" data-te-id="' + te.id + '" role="button" tabindex="0" aria-expanded="false">' +
                    statusBadge +
                    '<span class="threat-row-id">' + escapeHtml(te.id) + '</span>' +
                    '<span class="sev-pill ' + riskClass + '">' + (te.risk_level || '').toUpperCase() + '</span>' +
                    '<span class="threat-row-title">' + escapeHtml(te.title) + '</span>' +
                    (originText ? '<span class="threat-row-origin">' + escapeHtml(originText) + '</span>' : '') +
                '</div>';
            html += '<div class="threat-detail">' + renderThreatEventDetail(te) + '</div>';
        });
        html += '</div>';
    }

    // --- Gap 2: Risk Matrix (5x5) ---
    if (threats.length > 0) {
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Risk Matrix (SP 800-30 Table I-2)</h3>';
        html += renderRiskMatrix(threats);
    }

    // Assets affected (expandable)
    var assets = getAssetsAtPhase(phase);
    if (assets.length > 0) {
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Assets Affected (' + assets.length + ')</h3>';
        html += '<div class="phase-assets">';
        assets.forEach(function(a) {
            // Find full asset data
            var fullAsset = null;
            for (var ai = 0; ai < SAMPLE_ASSETS.length; ai++) {
                if (SAMPLE_ASSETS[ai].id === a.id) { fullAsset = SAMPLE_ASSETS[ai]; break; }
            }

            html +=
                '<div class="asset-row expandable" role="button" tabindex="0" aria-expanded="false">' +
                    '<span class="asset-row-name">' + escapeHtml(a.id) + ' ' + escapeHtml(a.name) + '</span>' +
                    '<span class="asset-row-threats">' + a.relevant_threats.join(', ') + '</span>' +
                '</div>';

            // Expandable detail
            html += '<div class="asset-detail">';
            if (fullAsset) {
                var cia = fullAsset.cia || {};
                html += '<div class="asset-detail-grid">';
                html += '<div class="asset-detail-item"><span class="ra-label">Owner</span><span>' + escapeHtml(fullAsset.owner || '') + '</span></div>';
                html += '<div class="asset-detail-item"><span class="ra-label">CIA</span><span class="ra-cia-row">' +
                    '<span class="ra-cia-item">C: ' + escapeHtml(cia.confidentiality || '--') + '</span>' +
                    '<span class="ra-cia-item">I: ' + escapeHtml(cia.integrity || '--') + '</span>' +
                    '<span class="ra-cia-item">A: ' + escapeHtml(cia.availability || '--') + '</span>' +
                    '</span></div>';
                html += '<div class="asset-detail-item"><span class="ra-label">Components</span><span>' + (fullAsset.components || []).join(', ') + '</span></div>';
                if (fullAsset.data_types && fullAsset.data_types.length > 0) {
                    html += '<div class="asset-detail-item"><span class="ra-label">Data Types</span><span>' + fullAsset.data_types.map(function(d) { return '<span class="pill pill-data">' + escapeHtml(d) + '</span>'; }).join(' ') + '</span></div>';
                }
                if (fullAsset.sla) {
                    html += '<div class="asset-detail-item"><span class="ra-label">SLA</span><span>' + escapeHtml(fullAsset.sla) + '</span></div>';
                }
                html += '</div>';
            }
            html += '</div>';
        });
        html += '</div>';
    }

    // --- Gap 4: Cross-Signal Insights (BUILD+ phases only) ---
    var raCI = cachedRiskAssessment || SAMPLE_RISK_ASSESSMENT;
    if (PHASE_ORDER.indexOf(phase) >= 1 && raCI.cross_signal_insights) {
        var visibleTeIds = threats.map(function(t) { return t.id; });
        var relevantInsights = raCI.cross_signal_insights.filter(function(insight) {
            return visibleTeIds.some(function(teId) { return insight.indexOf(teId) !== -1; });
        });

        if (relevantInsights.length > 0) {
            html += '<div class="phase-insights"><div class="phase-exec-label">Cross-Signal Insights</div>';
            relevantInsights.forEach(function(insight) {
                html += '<div class="insight-item"><span class="insight-icon">\u26A1</span>' + escapeHtml(insight) + '</div>';
            });
            html += '</div>';
        }
    }

    // --- Post-Assessment: Mission Impact ---
    var stData = SAMPLE_STAKEHOLDER_ACTIONS[phase];
    if (stData && stData.mission_impact) {
        var mi = stData.mission_impact;
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Mission Impact</h3>';
        html += '<div class="mission-impact">';
        html += '<div class="mission-row mission-row-revenue"><span class="mission-label">Revenue</span><span class="mission-text">' + escapeHtml(mi.revenue || '') + '</span></div>';
        html += '<div class="mission-row mission-row-sla"><span class="mission-label">SLA</span><span class="mission-text">' + escapeHtml(mi.sla || '') + '</span></div>';
        html += '<div class="mission-row mission-row-regulatory"><span class="mission-label">Regulatory</span><span class="mission-text">' + escapeHtml(mi.regulatory || '') + '</span></div>';
        html += '<div class="mission-row mission-row-supply"><span class="mission-label">Supply Chain</span><span class="mission-text">' + escapeHtml(mi.supply_chain || '') + '</span></div>';
        html += '</div>';
    }

    // --- Post-Assessment: Stakeholder Communication (SP 800-30 Step 3) ---
    if (stData && stData.stakeholders && stData.stakeholders.length > 0) {
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Stakeholder Communication (SP 800-30 Step 3)</h3>';
        html += '<div class="stakeholder-table"><div class="table-container"><table class="data-table">';
        html += '<thead><tr><th>Stakeholder</th><th>Key Finding</th><th>Urgency</th><th>Recommended Action</th><th>Decision Required</th></tr></thead><tbody>';
        stData.stakeholders.forEach(function(sh) {
            var urgClass = (sh.urgency || 'info').toLowerCase();
            var poamTags = '';
            if (sh.poam) {
                sh.poam.split(',').forEach(function(p) {
                    poamTags += ' <span class="ra-control-tag">' + escapeHtml(p.trim()) + '</span>';
                });
            }
            html +=
                '<tr>' +
                    '<td style="font-weight:600">' + escapeHtml(sh.role) + '</td>' +
                    '<td style="font-size:0.75rem">' + escapeHtml(sh.finding) + '</td>' +
                    '<td><span class="urgency-badge ' + urgClass + '">' + escapeHtml(sh.urgency.toUpperCase()) + '</span></td>' +
                    '<td style="font-size:0.75rem">' + escapeHtml(sh.action) + poamTags + '</td>' +
                    '<td style="font-size:0.75rem;color:var(--text-2);font-style:italic">' + (sh.decision ? escapeHtml(sh.decision) : '\u2014') + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div></div>';
    }

    // Controls tested (from threat events' controls)
    var controlIds = {};
    threats.forEach(function(te) {
        (te.controls || []).forEach(function(c) { controlIds[c] = true; });
    });
    var controlList = Object.keys(controlIds);
    if (controlList.length > 0) {
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Controls Tested (' + controlList.length + ')</h3>';
        html += '<div class="phase-controls">';

        // Find matching controls from compliance data
        var allControls = [];
        (cachedCompliance || SAMPLE_COMPLIANCE).frameworks.forEach(function(fw) {
            (fw.controls || []).forEach(function(ctrl) {
                if (controlIds[ctrl.id]) {
                    allControls.push(ctrl);
                }
            });
        });

        if (allControls.length > 0) {
            allControls.forEach(function(ctrl) {
                var fCount = ctrl.findings ? ctrl.findings.length : 0;
                var fText = ctrl.status === 'satisfied' ? 'satisfied' : (ctrl.status === 'not-assessed' ? 'not assessed' : fCount + ' finding' + (fCount !== 1 ? 's' : ''));
                html +=
                    '<div class="asset-row">' +
                        '<span class="status-icon ' + ctrl.status + '"></span>' +
                        '<span style="font-family:var(--mono);font-weight:600;color:var(--primary);font-size:0.75rem;min-width:100px">' + escapeHtml(ctrl.id) + '</span>' +
                        '<span style="flex:1;color:var(--text-2);font-size:0.8rem">' + escapeHtml(ctrl.title) + '</span>' +
                        '<span style="font-size:0.7rem;color:var(--text-3);font-family:var(--mono)">' + fText + '</span>' +
                    '</div>';
            });
        } else {
            controlList.forEach(function(cid) {
                html +=
                    '<div class="asset-row">' +
                        '<span style="font-family:var(--mono);font-weight:600;color:var(--primary);font-size:0.75rem">' + escapeHtml(cid) + '</span>' +
                    '</div>';
            });
        }

        html += '</div>';
    }

    // --- Post-Assessment: Reassessment & Monitoring (SP 800-30 Step 4) ---
    if (stData && stData.reassessment) {
        var reassess = stData.reassessment;
        html += '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Reassessment &amp; Monitoring (SP 800-30 Step 4)</h3>';
        html += '<div class="reassessment-card">';
        html += '<div class="reassessment-meta">';
        html += '<span class="reassessment-item"><span class="ra-label">Next Review</span><span>' + escapeHtml(reassess.next_review || '') + '</span></span>';
        var monBadge = reassess.monitoring ? '<span class="monitoring-badge active">Active</span>' : '<span class="monitoring-badge inactive">Inactive</span>';
        html += '<span class="reassessment-item"><span class="ra-label">Monitoring</span>' + monBadge + ' ' + escapeHtml(reassess.monitoring_detail || '') + '</span>';
        html += '</div>';
        if (reassess.triggers && reassess.triggers.length > 0) {
            html += '<div class="reassessment-triggers">';
            html += '<div class="phase-exec-label">Triggers for Reassessment</div>';
            html += '<ul class="ra-prepare-list">';
            reassess.triggers.forEach(function(t) { html += '<li>' + escapeHtml(t) + '</li>'; });
            html += '</ul></div>';
        }
        html += '</div>';
    }

    // --- Gap 5: NIST Table toggle for ALL phases with threats ---
    if (threats.length > 0) {
        var adversarialThreats = threats.filter(function(t) { return t.threat_source && t.threat_source.type === 'adversarial'; });
        var nonAdversarialThreats = threats.filter(function(t) { return !t.threat_source || t.threat_source.type !== 'adversarial'; });
        html +=
            '<div style="margin-top:24px">' +
                '<div class="ra-view-toggle">' +
                    '<button class="ra-toggle-btn active" data-view="cards">Threat Events (Cards)</button>' +
                    '<button class="ra-toggle-btn" data-view="nist-table">NIST Table I-5 / I-7</button>' +
                '</div>' +
                '<div class="ra-cards-view" style="display:none"></div>' +
                '<div class="ra-table-view" style="display:none">' +
                    renderAssetRiskSummary() +
                    renderNISTTableI5(adversarialThreats) +
                    renderNISTTableI7(nonAdversarialThreats) +
                '</div>' +
            '</div>';
    }

    // --- Assessment Context (collapsible, at bottom) ---
    var ra = cachedRiskAssessment || SAMPLE_RISK_ASSESSMENT;
    html += '<details class="phase-context"><summary>Assessment Context (SP 800-30 Step 1)</summary>';
    html += '<div class="phase-context-body">';
    html += '<div class="ra-detail-row"><span class="ra-label">Purpose</span><span class="ra-evidence">' + escapeHtml(ra.prepare.purpose) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Scope</span><span class="ra-evidence">' + escapeHtml(ra.prepare.scope.system + ' \u2014 ' + ra.prepare.scope.boundary) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Risk Model</span><span>' + escapeHtml(ra.prepare.risk_model) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Assessment Type</span><span>' + escapeHtml(ra.prepare.assessment_type) + '</span></div>';
    html += '<div class="ra-detail-row"><span class="ra-label">Time Frame</span><span>' + escapeHtml(ra.prepare.scope.time_frame) + '</span></div>';
    html += '</div></details>';

    return html;
}

function renderThreatEventDetail(evt) {
    var ts = evt.threat_source || {};
    var lk = evt.likelihood || {};
    var imp = evt.impact || {};
    var resp = evt.response || {};
    var cia = imp.cia || {};

    var confidenceHtml = '';
    if (evt.uncertainty) {
        var confMap = { low: 'HIGH', moderate: 'MODERATE', high: 'LOW' };
        var confClass = { low: 'conf-high', moderate: 'conf-moderate', high: 'conf-low' };
        confidenceHtml = '<span class="ra-confidence ' + (confClass[evt.uncertainty] || '') + '">Confidence: ' + (confMap[evt.uncertainty] || evt.uncertainty.toUpperCase()) + '</span>';
    }

    var html =
        '<div class="ra-detail-grid">' +
            '<div class="ra-detail-block">' +
                '<div class="ra-detail-heading">Threat Source</div>' +
                '<div class="ra-detail-row"><span class="ra-label">Type</span><span>' + escapeHtml(ts.type || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Actor</span><span>' + escapeHtml(ts.name || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Capability</span><span>' + escapeHtml(ts.capability || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Intent</span><span>' + escapeHtml(ts.intent || '') + '</span></div>' +
            '</div>' +
            '<div class="ra-detail-block">' +
                '<div class="ra-detail-heading">Likelihood</div>' +
                '<div class="ra-detail-row"><span class="ra-label">Initiation</span><span>' + escapeHtml(lk.initiation || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Impact</span><span>' + escapeHtml(lk.impact || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Overall</span><span class="ra-highlight">' + escapeHtml(lk.overall || '') + '</span></div>' +
                (lk.epss ? '<div class="ra-detail-row"><span class="ra-label">EPSS</span><span>' + lk.epss + '</span></div>' : '') +
                '<div class="ra-detail-row"><span class="ra-label">Evidence</span><span class="ra-evidence">' + escapeHtml(lk.evidence || '') + '</span></div>' +
            '</div>' +
            '<div class="ra-detail-block">' +
                '<div class="ra-detail-heading">Impact</div>' +
                '<div class="ra-detail-row"><span class="ra-label">Severity</span><span class="ra-highlight">' + escapeHtml(imp.severity || '') + '</span></div>' +
                (imp.impact_type ? '<div class="ra-detail-row"><span class="ra-label">Type</span><span class="ra-impact-type-label">' + escapeHtml(imp.impact_type) + '</span></div>' : '') +
                '<div class="ra-cia-row">' +
                    '<span class="ra-cia-item">C: ' + escapeHtml(cia.confidentiality || '--') + '</span>' +
                    '<span class="ra-cia-item">I: ' + escapeHtml(cia.integrity || '--') + '</span>' +
                    '<span class="ra-cia-item">A: ' + escapeHtml(cia.availability || '--') + '</span>' +
                '</div>' +
                '<div class="ra-detail-row"><span class="ra-label">Business</span><span class="ra-evidence">' + escapeHtml(imp.business || '') + '</span></div>' +
            '</div>' +
            '<div class="ra-detail-block">' +
                '<div class="ra-detail-heading">Risk Determination</div>' +
                '<div class="ra-detail-row"><span class="ra-label">Response</span><span class="ra-response-type ' + (resp.type || '') + '">' + escapeHtml((resp.type || '').toUpperCase()) + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Action</span><span class="ra-evidence">' + escapeHtml(resp.description || '') + '</span></div>' +
                '<div class="ra-detail-row"><span class="ra-label">Deadline</span><span>' + escapeHtml(resp.deadline || '') + '</span></div>' +
                confidenceHtml +
                '<div class="ra-detail-row"><span class="ra-label">Controls</span><span class="ra-controls">' + (evt.controls || []).map(function(c) { return '<span class="ra-control-tag">' + escapeHtml(c) + '</span>'; }).join(' ') + '</span></div>' +
            '</div>' +
        '</div>';

    // Vulnerabilities
    if ((evt.vulnerabilities && evt.vulnerabilities.length > 0) || (evt.predisposing_conditions && evt.predisposing_conditions.length > 0)) {
        html += '<div class="ra-vuln-conditions-block"><div class="ra-detail-heading">Vulnerabilities &amp; Predisposing Conditions</div><div class="ra-vuln-conditions-grid">';
        if (evt.vulnerabilities && evt.vulnerabilities.length > 0) {
            html += '<div class="ra-vuln-list">';
            evt.vulnerabilities.forEach(function(v) {
                html += '<div class="ra-vuln-item"><span class="ra-vuln-id">' + escapeHtml(v.id) + '</span><span class="ra-vuln-desc">' + escapeHtml(v.description) + '</span><span class="sev-pill ' + (v.severity || 'medium') + '">' + (v.severity || 'MEDIUM').toUpperCase() + '</span></div>';
            });
            html += '</div>';
        }
        if (evt.predisposing_conditions && evt.predisposing_conditions.length > 0) {
            html += '<div class="ra-predisposing"><div class="ra-predisposing-label">Predisposing Conditions</div><ul class="ra-prepare-list">';
            evt.predisposing_conditions.forEach(function(pc) { html += '<li>' + escapeHtml(pc) + '</li>'; });
            html += '</ul></div>';
        }
        html += '</div></div>';
    }

    return html;
}

function renderPipelineSteps(steps) {
    var html = '<div class="pipeline-steps">';

    steps.forEach(function(step) {
        var resultText = '';
        var resultClass = '';
        if (step.status === 'skipped') {
            resultText = 'skipped';
            resultClass = 'skipped-result';
        } else if (step.id === 'gate') {
            resultText = step.status === 'blocked' ? 'DATO' : 'PASS';
            resultClass = step.status === 'blocked' ? 'high-count' : 'zero';
        } else if (step.id === 'epss') {
            resultText = step.findings + '/' + (step.breakdown.total_cves || step.findings) + ' enriched';
            resultClass = 'info-result';
        } else {
            resultText = step.findings + ' ' + (step.findings === 1 ? 'finding' : 'findings');
            if (step.findings === 0) resultClass = 'zero';
            else if (step.findings <= 3) resultClass = 'low-count';
            else resultClass = 'high-count';
        }

        var breakdownKeys = Object.keys(step.breakdown || {});

        html +=
            '<div class="pipeline-row" role="button" tabindex="0" aria-expanded="false" data-step-id="' + step.id + '">' +
                '<span class="step-icon ' + step.status + '"></span>' +
                '<span class="step-tool">' + escapeHtml(step.tool) + '</span>' +
                '<span class="step-scanner">' + escapeHtml(step.scanner) + '</span>' +
                '<span class="step-result ' + resultClass + '">' + escapeHtml(resultText) + '</span>' +
                '<span class="step-duration">' + formatDuration(step.duration_ms) + '</span>' +
            '</div>';

        html += '<div class="step-breakdown">';
        if (step.detail) {
            html += '<div class="step-detail-text">' + escapeHtml(step.detail) + '</div>';
        }

        // Meta row
        var metaParts = [];
        if (step.version) metaParts.push('<span class="meta-item"><span class="meta-key">Version</span> ' + escapeHtml(step.version) + '</span>');
        if (step.rules_run) metaParts.push('<span class="meta-item"><span class="meta-key">Rules</span> ' + step.rules_run + '</span>');
        if (step.files_scanned) metaParts.push('<span class="meta-item"><span class="meta-key">Files</span> ' + step.files_scanned + '</span>');
        if (step.packages_scanned) metaParts.push('<span class="meta-item"><span class="meta-key">Packages</span> ' + step.packages_scanned + '</span>');
        if (step.sbom_format) metaParts.push('<span class="meta-item"><span class="meta-key">SBOM</span> ' + escapeHtml(step.sbom_format) + '</span>');
        if (step.commits_scanned) metaParts.push('<span class="meta-item"><span class="meta-key">Commits</span> ' + step.commits_scanned + '</span>');
        if (step.checks_run) metaParts.push('<span class="meta-item"><span class="meta-key">Checks</span> ' + step.checks_run + '</span>');
        if (step.resources_scanned) metaParts.push('<span class="meta-item"><span class="meta-key">Resources</span> ' + step.resources_scanned + '</span>');
        if (step.policies_evaluated) metaParts.push('<span class="meta-item"><span class="meta-key">Policies</span> ' + step.policies_evaluated + '</span>');
        if (step.mode) metaParts.push('<span class="meta-item"><span class="meta-key">Mode</span> ' + escapeHtml(step.mode) + '</span>');
        if (step.tokens_input) metaParts.push('<span class="meta-item"><span class="meta-key">Tokens in</span> ' + step.tokens_input.toLocaleString() + '</span>');
        if (step.tokens_output) metaParts.push('<span class="meta-item"><span class="meta-key">Tokens out</span> ' + step.tokens_output.toLocaleString() + '</span>');
        if (step.cache_hit_rate) metaParts.push('<span class="meta-item"><span class="meta-key">Cache</span> ' + escapeHtml(step.cache_hit_rate) + '</span>');

        if (metaParts.length > 0) {
            html += '<div class="step-meta-row">' + metaParts.join('') + '</div>';
        }

        if (breakdownKeys.length > 0) {
            html += '<div class="step-breakdown-chips">';
            breakdownKeys.forEach(function(key) {
                html +=
                    '<div class="breakdown-item">' +
                        '<span class="breakdown-dot" style="background:' + getBreakdownColor(key) + '"></span>' +
                        '<span class="breakdown-label">' + escapeHtml(key) + '</span>' +
                        '<span class="breakdown-val">' + step.breakdown[key] + '</span>' +
                    '</div>';
            });
            html += '</div>';
        }

        html += '</div>';
    });

    html += '</div>';
    return html;
}

// ---- SBOM Content ----

function renderSBOMContent() {
    var html = '<h2 class="section-title" style="margin-bottom:20px">Software Bill of Materials</h2>';

    html +=
        '<div class="sbom-summary-card">' +
            '<div class="sbom-stats">' +
                '<div class="metric-card"><div class="metric-value">7</div><div class="metric-label">Components</div><div class="metric-detail">6 direct (source scan)</div></div>' +
                '<div class="metric-card"><div class="metric-value">5</div><div class="metric-label">Vulnerable</div><div class="metric-detail">1 cr / 2 high / 2 med</div></div>' +
                '<div class="metric-card"><div class="metric-value">0</div><div class="metric-label">License Risks</div><div class="metric-detail">All permissive</div></div>' +
            '</div>' +
            '<a href="http://dtrack.miata.cloud/projects/5911f30c-1b3d-4282-8fce-da07a4a9dbc6" target="_blank" class="sbom-dt-link">Open in Dependency-Track \u2192</a>' +
        '</div>';

    html +=
        '<h3 class="section-title" style="margin-bottom:12px;font-size:0.95rem">Vulnerable Components</h3>' +
        '<div class="table-container">' +
            '<table class="data-table">' +
                '<thead><tr><th>Component</th><th>Version</th><th>CVEs</th><th>Severity</th><th>Fixed In</th></tr></thead>' +
                '<tbody>' +
                    '<tr><td>cryptography</td><td style="font-family:var(--mono)">3.4.6</td><td>CVE-2023-23931, CVE-2023-49083</td><td><span class="sev-pill critical">CRITICAL</span></td><td style="font-family:var(--mono)">41.0.0+</td></tr>' +
                    '<tr><td>pyjwt</td><td style="font-family:var(--mono)">1.7.1</td><td>CVE-2022-29217</td><td><span class="sev-pill high">HIGH</span></td><td style="font-family:var(--mono)">2.4.0</td></tr>' +
                    '<tr><td>requests</td><td style="font-family:var(--mono)">2.25.0</td><td>CVE-2023-32681</td><td><span class="sev-pill high">HIGH</span></td><td style="font-family:var(--mono)">2.31.0</td></tr>' +
                    '<tr><td>fastapi</td><td style="font-family:var(--mono)">0.104.0</td><td>CVE-2024-24762</td><td><span class="sev-pill medium">MEDIUM</span></td><td style="font-family:var(--mono)">0.109.1</td></tr>' +
                    '<tr><td>uvicorn</td><td style="font-family:var(--mono)">0.24.0</td><td>CVE-2024-24763</td><td><span class="sev-pill medium">MEDIUM</span></td><td style="font-family:var(--mono)">0.25.0</td></tr>' +
                '</tbody>' +
            '</table>' +
        '</div>';

    // Full component inventory
    html +=
        '<h3 class="section-title" style="margin-bottom:12px;margin-top:20px;font-size:0.95rem">Full Component Inventory</h3>' +
        '<div class="table-container">' +
            '<table class="data-table">' +
                '<thead><tr><th>Component</th><th>Version</th><th>Type</th><th>License</th><th>Status</th></tr></thead>' +
                '<tbody>' +
                    '<tr><td>cryptography</td><td style="font-family:var(--mono)">3.4.6</td><td>Library</td><td>Apache-2.0 / BSD-3</td><td><span class="sev-pill critical">2 CVEs</span></td></tr>' +
                    '<tr><td>pyjwt</td><td style="font-family:var(--mono)">1.7.1</td><td>Library</td><td>MIT</td><td><span class="sev-pill high">1 CVE</span></td></tr>' +
                    '<tr><td>requests</td><td style="font-family:var(--mono)">2.25.0</td><td>Library</td><td>Apache-2.0</td><td><span class="sev-pill high">1 CVE</span></td></tr>' +
                    '<tr><td>fastapi</td><td style="font-family:var(--mono)">0.104.0</td><td>Framework</td><td>MIT</td><td><span class="sev-pill medium">1 CVE</span></td></tr>' +
                    '<tr><td>uvicorn</td><td style="font-family:var(--mono)">0.24.0</td><td>Server</td><td>BSD-3</td><td><span class="sev-pill medium">1 CVE</span></td></tr>' +
                    '<tr><td>pydantic</td><td style="font-family:var(--mono)">2.5.0</td><td>Library</td><td>MIT</td><td style="color:var(--success)">Clean</td></tr>' +
                '</tbody>' +
            '</table>' +
        '</div>';

    // DT integration note
    html +=
        '<div class="reassessment-card" style="margin-top:16px">' +
            '<div class="phase-exec-label">Continuous SBOM Monitoring</div>' +
            '<p style="font-size:0.8rem;color:var(--text-2);line-height:1.6">SBOM is automatically uploaded to Dependency-Track on every merge to main via CI pipeline (build-dast.yml). DT continuously monitors for new CVEs against all components and sends alerts when new vulnerabilities are published.</p>' +
            '<div class="reassessment-meta" style="margin-top:12px">' +
                '<span class="reassessment-item"><span class="ra-label">Project</span><span>payment-api v1.0.0</span></span>' +
                '<span class="reassessment-item"><span class="ra-label">Format</span><span>CycloneDX 1.5 (JSON)</span></span>' +
                '<span class="reassessment-item"><span class="ra-label">Generator</span><span>Syft</span></span>' +
                '<span class="reassessment-item"><span class="ra-label">Monitoring</span><span class="monitoring-badge active">Active</span></span>' +
            '</div>' +
        '</div>';

    return html;
}

// ---- Compliance Content ----

function renderComplianceContent() {
    var data = cachedCompliance || SAMPLE_COMPLIANCE;
    var frameworks = (data && data.frameworks) || [];

    var html = '<div class="section-header-row"><h2 class="section-title">Compliance Status</h2></div>';

    if (frameworks.length === 0) {
        return html + '<div class="loading-placeholder"><span>No compliance data available.</span></div>';
    }

    frameworks.forEach(function(fw, fwIdx) {
        var pct = fw.total > 0 ? ((fw.satisfied / fw.total) * 100).toFixed(0) : 0;
        var progressColor = pct >= 70 ? 'var(--success)' : pct >= 40 ? 'var(--warning)' : 'var(--danger)';
        var expandedClass = fwIdx === 0 ? ' expanded' : '';

        var sortedControls = sortControls(fw.controls || []);

        html +=
            '<div class="framework-block' + expandedClass + '" data-fw-id="' + escapeHtml(fw.id) + '">' +
                '<div class="framework-header" role="button" tabindex="0" aria-expanded="' + (fwIdx === 0 ? 'true' : 'false') + '">' +
                    '<span class="framework-toggle">&#9654;</span>' +
                    '<span class="framework-name">' + escapeHtml(fw.name) + '</span>' +
                    '<div class="framework-progress-container">' +
                        '<div class="framework-progress-bar">' +
                            '<div class="framework-progress-fill" style="width:' + pct + '%;background:' + progressColor + '"></div>' +
                        '</div>' +
                        '<span class="framework-progress-text">' + fw.satisfied + '/' + fw.total + ' (' + pct + '%)</span>' +
                    '</div>' +
                '</div>' +
                '<div class="framework-body">';

        sortedControls.forEach(function(ctrl) {
            var hasFindingsClass = (ctrl.findings && ctrl.findings.length > 0) ? ' has-findings' : '';
            var findingsCountText = '';
            if (ctrl.status === 'satisfied') findingsCountText = 'satisfied';
            else if (ctrl.status === 'not-assessed') findingsCountText = 'not assessed';
            else findingsCountText = ctrl.findings.length + ' finding' + (ctrl.findings.length !== 1 ? 's' : '');
            var findingsCountClass = (ctrl.findings && ctrl.findings.length > 0) ? ' has-findings' : '';

            html +=
                '<div class="control-row' + hasFindingsClass + '" role="button" tabindex="0" aria-expanded="false">' +
                    '<span class="status-icon ' + ctrl.status + '"></span>' +
                    '<span class="control-id">' + escapeHtml(ctrl.id) + '</span>' +
                    '<span class="control-title">' + escapeHtml(ctrl.title) + '</span>' +
                    '<span class="control-findings-count' + findingsCountClass + '">' + findingsCountText + '</span>' +
                '</div>';

            if (ctrl.findings && ctrl.findings.length > 0) {
                html += '<div class="control-findings-list">';
                ctrl.findings.forEach(function(f) {
                    var overrideBadge = '';
                    if (f.override) {
                        var oDays = daysUntil(f.override.expires);
                        var oLabel = f.override.type.toUpperCase() + ' ' + oDays + 'd';
                        overrideBadge = '<span class="finding-override-badge ' + f.override.type + '">' + oLabel + '</span>';
                    }
                    html +=
                        '<div class="finding-item">' +
                            '<span class="finding-sev ' + f.severity + '">' + f.severity.toUpperCase() + '</span>' +
                            '<span class="finding-scanner">' + escapeHtml(f.scanner) + ':</span>' +
                            '<span class="finding-msg">' + escapeHtml(f.message) + '</span>' +
                            overrideBadge +
                        '</div>';
                });
                html += '</div>';
            } else {
                html += '<div class="control-findings-list"></div>';
            }
        });

        html += '</div></div>';
    });

    return html;
}

// ---- POA&M Content ----

var poamSortCol = null;
var poamSortDir = 'asc';

function renderPOAMContent() {
    var items = (cachedPOAM || SAMPLE_POAM).items;
    var html = '<div class="section-header-row"><h2 class="section-title">Plan of Action &amp; Milestones (POA&amp;M)</h2></div>';

    // Summary stats
    var overdue = items.filter(function(i) { return daysUntil(i.deadline) < 0; }).length;
    var inProgress = items.filter(function(i) { return i.status === 'in-progress'; }).length;
    var open = items.filter(function(i) { return i.status === 'open'; }).length;
    var critical = items.filter(function(i) { return i.severity === 'critical'; }).length;
    var high = items.filter(function(i) { return i.severity === 'high'; }).length;

    html += '<div class="overview-metrics" style="margin-bottom:20px">';
    html += '<div class="metric-card"><div class="metric-value">' + items.length + '</div><div class="metric-label">Total Items</div><div class="metric-detail">' + overdue + ' overdue</div></div>';
    html += '<div class="metric-card"><div class="metric-value" style="color:var(--danger)">' + critical + '</div><div class="metric-label">Critical</div></div>';
    html += '<div class="metric-card"><div class="metric-value" style="color:var(--warning)">' + high + '</div><div class="metric-label">High</div></div>';
    html += '<div class="metric-card"><div class="metric-value" style="color:var(--info)">' + inProgress + '</div><div class="metric-label">In Progress</div><div class="metric-detail">' + open + ' open</div></div>';
    html += '</div>';

    // Grouped by severity
    var groups = [
        { label: 'Critical', severity: 'critical', items: items.filter(function(i) { return i.severity === 'critical'; }) },
        { label: 'High', severity: 'high', items: items.filter(function(i) { return i.severity === 'high'; }) },
        { label: 'Medium', severity: 'medium', items: items.filter(function(i) { return i.severity === 'medium'; }) },
        { label: 'Low', severity: 'low', items: items.filter(function(i) { return i.severity === 'low'; }) }
    ];

    groups.forEach(function(group) {
        if (group.items.length === 0) return;

        html += '<div style="margin-bottom:16px">';
        html += '<div style="font-size:0.7rem;font-weight:700;color:var(--text-3);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px">' + group.label + ' (' + group.items.length + ')</div>';

        group.items.forEach(function(item) {
            var days = daysUntil(item.deadline);
            var deadlineClass = days < 0 ? 'deadline-urgent' : (days < 7 ? 'deadline-urgent' : 'deadline-ok');
            var deadlineText = days < 0 ? (Math.abs(days) + 'd overdue') : (days + 'd remaining');

            var statusColor = 'var(--text-3)';
            if (item.status === 'in-progress') statusColor = 'var(--info)';
            else if (item.status === 'completed') statusColor = 'var(--success)';

            // Progress calc
            var rem = item.remediation || {};
            var ms = rem.milestones || [];
            var completedMs = ms.filter(function(m) { return m.status === 'completed'; }).length;
            var progressPct = ms.length > 0 ? Math.round(completedMs / ms.length * 100) : 0;

            // Asset names
            var assetNames = (item.assets || []).map(function(aId) {
                for (var ai = 0; ai < SAMPLE_ASSETS.length; ai++) {
                    if (SAMPLE_ASSETS[ai].id === aId) return SAMPLE_ASSETS[ai].name;
                }
                return aId;
            });

            html +=
                '<div class="poam-card" role="button" tabindex="0" aria-expanded="false">' +
                    '<div class="poam-card-header">' +
                        '<span class="poam-id">' + escapeHtml(item.id) + '</span>' +
                        '<span class="sev-pill ' + item.severity + '">' + item.severity.toUpperCase() + '</span>' +
                        '<span class="poam-finding">' + escapeHtml(item.finding) + '</span>' +
                        '<span class="poam-meta">' +
                            '<span class="scanner-badge">' + escapeHtml(item.scanner) + '</span>' +
                            '<span class="ra-control-tag">' + escapeHtml(item.control) + '</span>' +
                        '</span>' +
                        '<span class="' + deadlineClass + '" style="font-family:var(--mono);font-size:0.7rem;min-width:80px;text-align:right">' + deadlineText + '</span>' +
                        '<span style="color:' + statusColor + ';font-size:0.7rem;font-weight:600;min-width:70px;text-align:right">' + item.status.toUpperCase().replace('-', ' ') + '</span>' +
                    '</div>' +
                    '<div class="poam-card-detail">';

            // Affected assets
            if (assetNames.length > 0) {
                html += '<div class="poam-detail-row"><span class="ra-label">Assets</span><span>' + assetNames.join(', ') + '</span></div>';
            }
            if (item.threat_event) {
                html += '<div class="poam-detail-row"><span class="ra-label">Threat Event</span><span style="font-family:var(--mono);font-weight:600">' + escapeHtml(item.threat_event) + '</span></div>';
            }
            html += '<div class="poam-detail-row"><span class="ra-label">Responsible</span><span>' + escapeHtml(item.responsible) + '</span></div>';

            // Remediation plan
            if (rem.plan) {
                html += '<div class="poam-remediation"><div class="phase-exec-label">Remediation Plan</div>';
                html += '<p style="font-size:0.8rem;color:var(--text-2);line-height:1.6;margin-bottom:12px">' + escapeHtml(rem.plan) + '</p>';

                // Milestones with progress bar
                if (ms.length > 0) {
                    html += '<div class="poam-progress-bar"><div class="confidence-bar-track" style="max-width:none"><div class="confidence-bar-fill" style="width:' + progressPct + '%"></div></div><span style="font-size:0.7rem;color:var(--text-2);font-family:var(--mono)">' + completedMs + '/' + ms.length + ' (' + progressPct + '%)</span></div>';

                    html += '<div class="poam-milestones">';
                    ms.forEach(function(m) {
                        var msIcon = m.status === 'completed' ? 'completed' : (m.status === 'in-progress' ? 'in-progress' : 'open');
                        var msColor = m.status === 'completed' ? 'var(--success)' : (m.status === 'in-progress' ? 'var(--info)' : 'var(--text-3)');
                        html +=
                            '<div class="poam-milestone">' +
                                '<span class="poam-ms-icon ' + msIcon + '"></span>' +
                                '<span class="poam-ms-text">' + escapeHtml(m.step) + '</span>' +
                                '<span class="poam-ms-date" style="color:' + msColor + '">' + escapeHtml(m.target) + '</span>' +
                            '</div>';
                    });
                    html += '</div>';
                }

                // Cost and risk
                html += '<div style="display:flex;gap:24px;margin-top:12px">';
                if (rem.cost_estimate) {
                    html += '<div class="poam-detail-row"><span class="ra-label">Cost</span><span>' + escapeHtml(rem.cost_estimate) + '</span></div>';
                }
                if (rem.risk_if_delayed) {
                    html += '<div class="poam-detail-row" style="flex:1"><span class="ra-label">Risk if Delayed</span><span style="color:var(--danger);font-size:0.75rem">' + escapeHtml(rem.risk_if_delayed) + '</span></div>';
                }
                html += '</div>';

                html += '</div>';
            }

            html += '</div></div>';
        });

        html += '</div>';
    });

    return html;
}

// ---- Timeline Content ----

function renderTimelineContent() {
    var runs = (SAMPLE_TIMELINE && SAMPLE_TIMELINE.runs) || [];

    var html = '<h2 class="section-title" style="margin-bottom:16px">Assessment Timeline</h2>';

    if (runs.length === 0) {
        return html + '<div class="loading-placeholder"><span>No historical data available.</span></div>';
    }

    var maxScore = 0;
    var maxFindings = 0;
    runs.forEach(function(r) {
        if (r.risk_score > maxScore) maxScore = r.risk_score;
        if (r.findings > maxFindings) maxFindings = r.findings;
    });
    maxScore = Math.max(maxScore, 1);
    maxFindings = Math.max(maxFindings, 1);

    var chartW = 720;
    var chartH = 160;
    var padL = 40;
    var padR = 20;
    var padT = 20;
    var padB = 40;
    var plotW = chartW - padL - padR;
    var plotH = chartH - padT - padB;

    var stepX = runs.length > 1 ? plotW / (runs.length - 1) : plotW;

    var riskPoints = [];
    var findingsPoints = [];
    runs.forEach(function(run, i) {
        var x = padL + (i * stepX);
        var yRisk = padT + plotH - (run.risk_score / maxScore * plotH);
        var yFind = padT + plotH - (run.findings / maxFindings * plotH);
        riskPoints.push({ x: x, y: yRisk, run: run });
        findingsPoints.push({ x: x, y: yFind, run: run });
    });

    var riskPath = riskPoints.map(function(p, i) { return (i === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');
    var findingsPath = findingsPoints.map(function(p, i) { return (i === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');

    html += '<div class="timeline-chart-wrapper">';

    html +=
        '<div class="timeline-legend">' +
            '<span class="timeline-legend-item"><span class="legend-line" style="background:var(--danger)"></span> Risk Score</span>' +
            '<span class="timeline-legend-item"><span class="legend-line" style="background:var(--info)"></span> Total Findings</span>' +
        '</div>';

    html += '<svg class="timeline-svg" viewBox="0 0 ' + chartW + ' ' + chartH + '" preserveAspectRatio="xMidYMid meet">';

    for (var g = 0; g <= 4; g++) {
        var gy = padT + (plotH / 4 * g);
        html += '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (chartW - padR) + '" y2="' + gy.toFixed(1) + '" stroke="var(--border)" stroke-width="0.5" stroke-dasharray="4,4"/>';
    }

    for (var g = 0; g <= 4; g++) {
        var gy = padT + (plotH / 4 * g);
        var yVal = Math.round(maxScore - (maxScore / 4 * g));
        html += '<text x="' + (padL - 8) + '" y="' + (gy + 3).toFixed(1) + '" text-anchor="end" fill="var(--text-3)" font-size="9" font-family="var(--mono)">' + yVal + '</text>';
    }

    html += '<path d="' + findingsPath + '" fill="none" stroke="var(--info)" stroke-width="1.5" stroke-opacity="0.4"/>';
    html += '<path d="' + riskPath + '" fill="none" stroke="var(--danger)" stroke-width="2"/>';

    riskPoints.forEach(function(p) {
        var gateColor = p.run.gate === 'DATO' ? 'var(--danger)' : 'var(--success)';
        html += '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="4" fill="' + gateColor + '" stroke="var(--bg)" stroke-width="2"/>';
        var dateStr = new Date(p.run.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        html += '<text x="' + p.x.toFixed(1) + '" y="' + (chartH - 8) + '" text-anchor="middle" fill="var(--text-3)" font-size="9" font-family="var(--mono)">' + escapeHtml(dateStr) + '</text>';
    });

    html += '</svg>';

    html += '<div class="timeline-table"><table class="data-table"><thead><tr>' +
        '<th>Date</th><th>Gate</th><th>Risk</th><th>Findings</th><th>Critical</th><th>High</th><th>SAR Coverage</th>' +
        '</tr></thead><tbody>';

    for (var i = runs.length - 1; i >= 0; i--) {
        var run = runs[i];
        var gateClass = run.gate === 'DATO' ? 'dato' : 'ato';
        html +=
            '<tr>' +
                '<td style="font-family:var(--mono);color:var(--text-2)">' + formatTimestamp(run.timestamp) + '</td>' +
                '<td><span class="gate-badge-inline ' + gateClass + '">' + escapeHtml(run.gate) + '</span></td>' +
                '<td style="font-family:var(--mono);font-weight:600">' + run.risk_score + '</td>' +
                '<td style="font-family:var(--mono)">' + run.findings + '</td>' +
                '<td style="color:var(--danger);font-family:var(--mono)">' + (run.critical || 0) + '</td>' +
                '<td style="color:var(--warning);font-family:var(--mono)">' + (run.high || 0) + '</td>' +
                '<td style="font-family:var(--mono)">' + (run.satisfied_pct || '--') + '%</td>' +
            '</tr>';
    }

    html += '</tbody></table></div></div>';
    return html;
}

// ---- Asset Risk Summary Table ----

function ciaAbbr(level) {
    var l = (level || '').toLowerCase();
    var letter = l === 'high' ? 'H' : l === 'moderate' ? 'M' : l === 'low' ? 'L' : '-';
    var cls = l === 'high' ? 'cia-high' : l === 'moderate' ? 'cia-moderate' : 'cia-low';
    return '<span class="cia-abbr ' + cls + '">' + letter + '</span>';
}

function renderAssetRiskSummary() {
    var html =
        '<div class="nist-table-section">' +
            '<div class="nist-table-label">Asset Risk Summary</div>' +
            '<div class="table-container">' +
                '<table class="data-table">' +
                    '<thead><tr>' +
                        '<th>Asset</th><th>Owner</th><th>CIA</th><th>Components</th><th>Data Types</th><th>Threats</th><th>Risk</th>' +
                    '</tr></thead><tbody>';

    SAMPLE_ASSETS.forEach(function(a) {
        var ciaHtml = ciaAbbr(a.cia.confidentiality) + '/' + ciaAbbr(a.cia.integrity) + '/' + ciaAbbr(a.cia.availability);
        var compHtml = a.components.map(function(c) { return '<span class="pill pill-framework">' + escapeHtml(c) + '</span>'; }).join(' ');
        var dtHtml = a.data_types.length > 0 ? a.data_types.map(function(d) { return '<span class="pill pill-data">' + escapeHtml(d) + '</span>'; }).join(' ') : '<span style="color:var(--text-3)">&mdash;</span>';
        var teHtml = a.threat_events.join(', ');
        var riskClass = a.aggregate_risk.replace(' ', '-');

        html +=
            '<tr>' +
                '<td style="font-weight:600;color:var(--text)">' + escapeHtml(a.name) + '</td>' +
                '<td style="color:var(--text-2)">' + escapeHtml(a.owner) + '</td>' +
                '<td style="white-space:nowrap">' + ciaHtml + '</td>' +
                '<td>' + compHtml + '</td>' +
                '<td>' + dtHtml + '</td>' +
                '<td style="font-family:var(--mono);font-size:0.7rem;color:var(--text-2)">' + escapeHtml(teHtml) + '</td>' +
                '<td><span class="sev-pill ' + riskClass + '">' + a.aggregate_risk.toUpperCase() + '</span></td>' +
            '</tr>';
    });

    html += '</tbody></table></div></div>';
    return html;
}

// ---- NIST Table I-5 ----

function nistLevelSpan(val) {
    if (!val || val === 'n/a') return '<span class="nist-level" style="color:var(--text-3)">N/A</span>';
    var cls = (val || '').toLowerCase().replace(' ', '-');
    return '<span class="nist-level ' + cls + '">' + escapeHtml(val) + '</span>';
}

function renderNISTTableI5(threatEvents) {
    var adversarial = threatEvents.filter(function(e) { return e.threat_source && e.threat_source.type === 'adversarial'; });
    if (adversarial.length === 0) return '';

    var html =
        '<div class="nist-table-section">' +
            '<div class="nist-table-label">Table I-5: Adversarial Risk</div>' +
            '<div class="nist-table-sublabel">Assessment of risk from adversarial threat events per SP 800-30 Rev 1</div>' +
            '<div class="nist-table-container">' +
                '<table class="nist-table">' +
                    '<thead><tr>' +
                        '<th class="sticky-left nist-col-event">Threat Event</th>' +
                        '<th class="sticky-left-2 nist-col-source">Threat Sources</th>' +
                        '<th class="nist-col-level">Capability</th>' +
                        '<th class="nist-col-level">Intent</th>' +
                        '<th class="nist-col-level">Targeting</th>' +
                        '<th class="nist-col-level">Relevance</th>' +
                        '<th class="nist-col-level">Likelihood of Attack Initiation</th>' +
                        '<th class="nist-col-vuln">Vulnerabilities &amp; Predisposing Conditions</th>' +
                        '<th class="nist-col-level">Severity &amp; Pervasiveness</th>' +
                        '<th class="nist-col-level">Likelihood Initiated Attack Succeeds</th>' +
                        '<th class="nist-col-level">Overall Likelihood</th>' +
                        '<th class="nist-col-level">Level of Impact</th>' +
                        '<th class="sticky-right nist-col-risk">Risk</th>' +
                    '</tr></thead><tbody>';

    adversarial.forEach(function(evt) {
        var ts = evt.threat_source || {};
        var lk = evt.likelihood || {};
        var imp = evt.impact || {};

        var vulnItems = '';
        if (evt.vulnerabilities && evt.vulnerabilities.length > 0) {
            vulnItems += '<ul class="nist-vuln-list">';
            evt.vulnerabilities.forEach(function(v) { vulnItems += '<li>' + escapeHtml(v.description) + '</li>'; });
            vulnItems += '</ul>';
        }
        if (evt.predisposing_conditions && evt.predisposing_conditions.length > 0) {
            vulnItems += '<ul class="nist-vuln-list">';
            evt.predisposing_conditions.forEach(function(pc) { vulnItems += '<li>' + escapeHtml(pc) + '</li>'; });
            vulnItems += '</ul>';
        }

        var sevLevels = (evt.vulnerabilities || []).map(function(v) { return v.severity || 'medium'; });
        var sevHtml = sevLevels.map(function(s) { return nistLevelSpan(s); }).join(', ');
        if (!sevHtml) sevHtml = '<span style="color:var(--text-3)">--</span>';

        var riskClass = (evt.risk_level || 'moderate').replace(' ', '-');
        var riskHtml = '<span class="sev-pill ' + riskClass + '">' + (evt.risk_level || '').toUpperCase() + '</span>' +
            '<div style="margin-top:4px;font-family:var(--mono);font-size:0.65rem;color:var(--text-2)">' + (evt.risk_score || 0) + '/100</div>';

        html +=
            '<tr>' +
                '<td class="sticky-left nist-col-event"><strong>' + escapeHtml(evt.id) + '</strong><br/><span style="color:var(--text-2)">' + escapeHtml(evt.title) + '</span></td>' +
                '<td class="sticky-left-2 nist-col-source">' + escapeHtml(ts.name || '') + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(ts.capability) + '</td>' +
                '<td class="nist-col-level" style="text-align:left;max-width:140px">' + escapeHtml(ts.intent || '') + '</td>' +
                '<td class="nist-col-level" style="text-align:left;max-width:140px">' + escapeHtml(ts.targeting || '') + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(evt.relevance) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.initiation) + '</td>' +
                '<td class="nist-col-vuln">' + vulnItems + '</td>' +
                '<td class="nist-col-level">' + sevHtml + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.impact) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.overall) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(imp.severity) + '</td>' +
                '<td class="sticky-right nist-col-risk">' + riskHtml + '</td>' +
            '</tr>';
    });

    html += '</tbody></table></div></div>';
    return html;
}

// ---- NIST Table I-7 ----

function renderNISTTableI7(threatEvents) {
    var nonAdversarial = threatEvents.filter(function(e) { return !e.threat_source || e.threat_source.type !== 'adversarial'; });
    if (nonAdversarial.length === 0) return '';

    var html =
        '<div class="nist-table-section">' +
            '<div class="nist-table-label">Table I-7: Non-Adversarial Risk</div>' +
            '<div class="nist-table-sublabel">Assessment of risk from non-adversarial threat events per SP 800-30 Rev 1</div>' +
            '<div class="nist-table-container">' +
                '<table class="nist-table">' +
                    '<thead><tr>' +
                        '<th class="sticky-left nist-col-event">Threat Event</th>' +
                        '<th class="sticky-left-2 nist-col-source">Threat Sources</th>' +
                        '<th style="min-width:180px">Range of Effects</th>' +
                        '<th class="nist-col-level">Relevance</th>' +
                        '<th class="nist-col-level">Likelihood of Event Occurring</th>' +
                        '<th class="nist-col-vuln">Vulnerabilities &amp; Predisposing Conditions</th>' +
                        '<th class="nist-col-level">Severity &amp; Pervasiveness</th>' +
                        '<th class="nist-col-level">Likelihood Event Results in Adverse Impact</th>' +
                        '<th class="nist-col-level">Overall Likelihood</th>' +
                        '<th class="nist-col-level">Level of Impact</th>' +
                        '<th class="sticky-right nist-col-risk">Risk</th>' +
                    '</tr></thead><tbody>';

    nonAdversarial.forEach(function(evt) {
        var ts = evt.threat_source || {};
        var lk = evt.likelihood || {};
        var imp = evt.impact || {};

        var vulnItems = '';
        if (evt.vulnerabilities && evt.vulnerabilities.length > 0) {
            vulnItems += '<ul class="nist-vuln-list">';
            evt.vulnerabilities.forEach(function(v) { vulnItems += '<li>' + escapeHtml(v.description) + '</li>'; });
            vulnItems += '</ul>';
        }
        if (evt.predisposing_conditions && evt.predisposing_conditions.length > 0) {
            vulnItems += '<ul class="nist-vuln-list">';
            evt.predisposing_conditions.forEach(function(pc) { vulnItems += '<li>' + escapeHtml(pc) + '</li>'; });
            vulnItems += '</ul>';
        }

        var sevLevels = (evt.vulnerabilities || []).map(function(v) { return v.severity || 'medium'; });
        var sevHtml = sevLevels.map(function(s) { return nistLevelSpan(s); }).join(', ');
        if (!sevHtml) sevHtml = '<span style="color:var(--text-3)">--</span>';

        var riskClass = (evt.risk_level || 'moderate').replace(' ', '-');
        var riskHtml = '<span class="sev-pill ' + riskClass + '">' + (evt.risk_level || '').toUpperCase() + '</span>' +
            '<div style="margin-top:4px;font-family:var(--mono);font-size:0.65rem;color:var(--text-2)">' + (evt.risk_score || 0) + '/100</div>';

        var rangeText = evt.range_of_effects || evt.narrative || '';

        html +=
            '<tr>' +
                '<td class="sticky-left nist-col-event"><strong>' + escapeHtml(evt.id) + '</strong><br/><span style="color:var(--text-2)">' + escapeHtml(evt.title) + '</span></td>' +
                '<td class="sticky-left-2 nist-col-source">' + escapeHtml(ts.name || '') + '</td>' +
                '<td style="max-width:220px;color:var(--text-2);font-size:0.65rem;line-height:1.4">' + escapeHtml(rangeText) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(evt.relevance) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.initiation && lk.initiation !== 'n/a' ? lk.initiation : lk.overall) + '</td>' +
                '<td class="nist-col-vuln">' + vulnItems + '</td>' +
                '<td class="nist-col-level">' + sevHtml + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.impact) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(lk.overall) + '</td>' +
                '<td class="nist-col-level">' + nistLevelSpan(imp.severity) + '</td>' +
                '<td class="sticky-right nist-col-risk">' + riskHtml + '</td>' +
            '</tr>';
    });

    html += '</tbody></table></div></div>';
    return html;
}

// ---- View Selection ----

function selectView(view) {
    currentView = view;
    updateLeftNavActiveStates();
    renderRightPanel(view);
}

function updateLeftNavActiveStates() {
    document.querySelectorAll('.nav-phase, .nav-section').forEach(function(el) {
        el.classList.remove('active');
    });
    var activePhase = document.querySelector('.nav-phase[data-phase="' + currentView + '"]');
    if (activePhase) activePhase.classList.add('active');
    var activeSection = document.querySelector('.nav-section[data-section="' + currentView + '"]');
    if (activeSection) activeSection.classList.add('active');

    // Update section icons
    document.querySelectorAll('.nav-section').forEach(function(el) {
        var icon = el.querySelector('.nav-section-icon');
        if (icon) {
            icon.textContent = el.classList.contains('active') ? "\u25C9" : "\u25CB";
        }
    });
}

// ---- Wire Right Panel Interactivity ----

function wireRightPanelInteractivity(view, container) {
    // Pipeline row expand/collapse
    container.querySelectorAll('.pipeline-row').forEach(function(row) {
        row.addEventListener('click', function() {
            var expanded = row.classList.toggle('expanded');
            row.setAttribute('aria-expanded', String(expanded));
        });
        row.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
        });
    });

    // Threat row expand/collapse
    container.querySelectorAll('.threat-row').forEach(function(row) {
        row.addEventListener('click', function() {
            var expanded = row.classList.toggle('expanded');
            row.setAttribute('aria-expanded', String(expanded));
        });
        row.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
        });
    });

    // Expandable asset rows
    container.querySelectorAll('.asset-row.expandable').forEach(function(row) {
        row.addEventListener('click', function() {
            var expanded = row.classList.toggle('expanded');
            row.setAttribute('aria-expanded', String(expanded));
        });
        row.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
        });
    });

    // Risk assessment event cards
    container.querySelectorAll('.ra-event-card').forEach(function(card) {
        card.addEventListener('click', function() {
            var expanded = card.classList.toggle('expanded');
            card.setAttribute('aria-expanded', String(expanded));
        });
        card.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); card.click(); }
        });
    });

    // NIST Table toggle
    container.querySelectorAll('.ra-toggle-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var viewType = btn.getAttribute('data-view');
            container.querySelectorAll('.ra-toggle-btn').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            var cardsView = container.querySelector('.ra-cards-view');
            var tableView = container.querySelector('.ra-table-view');
            if (viewType === 'cards') {
                if (cardsView) cardsView.style.display = '';
                if (tableView) tableView.style.display = 'none';
            } else {
                if (cardsView) cardsView.style.display = 'none';
                if (tableView) tableView.style.display = '';
            }
        });
    });

    // POA&M card expand/collapse
    container.querySelectorAll('.poam-card').forEach(function(card) {
        card.addEventListener('click', function() {
            var expanded = card.classList.toggle('expanded');
            card.setAttribute('aria-expanded', String(expanded));
        });
        card.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); card.click(); }
        });
    });

    // Collapsible cards
    container.querySelectorAll('.collapsible-header').forEach(function(hdr) {
        hdr.addEventListener('click', function() {
            var card = hdr.closest('.collapsible-card');
            var isCollapsed = card.getAttribute('data-collapsed') === 'true';
            card.setAttribute('data-collapsed', String(!isCollapsed));
            hdr.setAttribute('aria-expanded', String(isCollapsed));
        });
        hdr.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); hdr.click(); }
        });
    });

    // Framework expand/collapse (compliance view)
    container.querySelectorAll('.framework-header').forEach(function(hdr) {
        hdr.addEventListener('click', function() {
            var block = hdr.closest('.framework-block');
            var expanded = block.classList.toggle('expanded');
            hdr.setAttribute('aria-expanded', String(expanded));
        });
        hdr.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); hdr.click(); }
        });
    });

    // Control row expand/collapse (compliance view)
    container.querySelectorAll('.control-row.has-findings').forEach(function(row) {
        row.addEventListener('click', function() {
            var expanded = row.classList.toggle('expanded');
            row.setAttribute('aria-expanded', String(expanded));
        });
        row.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); }
        });
    });

    // POA&M sort (poam view)
    if (view === 'poam') {
        container.querySelectorAll('.sortable').forEach(function(th) {
            th.addEventListener('click', function() {
                var col = th.getAttribute('data-sort');
                if (poamSortCol === col) {
                    poamSortDir = poamSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    poamSortCol = col;
                    poamSortDir = 'asc';
                }

                container.querySelectorAll('th').forEach(function(h) { h.classList.remove('sort-asc', 'sort-desc'); });
                th.classList.add(poamSortDir === 'asc' ? 'sort-asc' : 'sort-desc');

                var items = (cachedPOAM || SAMPLE_POAM).items.slice();
                items.sort(function(a, b) {
                    var va = a[col] || '';
                    var vb = b[col] || '';
                    if (col === 'severity') {
                        var order = { critical: 0, high: 1, medium: 2, low: 3 };
                        va = order[va] !== undefined ? order[va] : 99;
                        vb = order[vb] !== undefined ? order[vb] : 99;
                    }
                    if (va < vb) return poamSortDir === 'asc' ? -1 : 1;
                    if (va > vb) return poamSortDir === 'asc' ? 1 : -1;
                    return 0;
                });

                var tbody = document.getElementById('poam-tbody');
                if (tbody) tbody.innerHTML = renderPOAMRows(items);
            });
        });
    }
}

// ---- Wire Left Panel Nav ----

function wireLeftPanelNav() {
    document.querySelectorAll('.nav-phase').forEach(function(el) {
        el.addEventListener('click', function() {
            var phase = el.getAttribute('data-phase');
            selectView(phase);
        });
    });

    document.querySelectorAll('.nav-section').forEach(function(el) {
        el.addEventListener('click', function() {
            var section = el.getAttribute('data-section');
            selectView(section);
        });
    });
}

// ---- Main Router Handler ----

async function handleRoute() {
    var app = document.getElementById('app');
    var route = getRoute();

    if (route.view === 'list') {
        currentProjectId = null;
        currentView = 'overview';
        cachedIndexData = null;
        cachedProject = null;

        var projectsData = await fetchJSON('/projects.json');
        var projects = (projectsData || SAMPLE_PROJECTS).projects || [];

        app.innerHTML =
            renderListHeader() +
            '<main>' + renderProjectListView(projects) + '</main>' +
            '<footer class="site-footer">' +
                '<div class="footer-brand">AI DevSecOps Platform</div>' +
                '<div class="footer-links">' +
                    '<a href="https://github.com/s1ns3nz0/ai-devsecops" target="_blank" rel="noopener noreferrer">GitHub</a>' +
                    '<a href="https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final" target="_blank" rel="noopener noreferrer">NIST SP 800-30</a>' +
                    '<a href="https://csrc.nist.gov/projects/risk-management/about-rmf" target="_blank" rel="noopener noreferrer">RMF</a>' +
                '</div>' +
            '</footer>';

        wireHeaderNav();

    } else if (route.view === 'detail') {
        currentProjectId = route.projectId;
        currentView = 'overview';

        var rawIndex = await fetchJSON('/projects/' + encodeURIComponent(route.projectId) + '/index.json');
        var indexData = rawIndex ? transformIndexData(rawIndex) : SAMPLE_INDEX;
        cachedIndexData = indexData;

        // Pre-fetch and transform SP800-30 data if available
        var rawSP = await fetchJSON('/projects/' + encodeURIComponent(route.projectId) + '/sp800-30.json');
        if (rawSP) { cachedRiskAssessment = transformSP80030(rawSP); }

        // Pre-fetch and transform SAR data
        var rawSAR = await fetchJSON('/projects/' + encodeURIComponent(route.projectId) + '/sar.json');
        if (rawSAR) { cachedCompliance = transformSAR(rawSAR); }

        // Pre-fetch and transform POA&M data
        var rawPOAM = await fetchJSON('/projects/' + encodeURIComponent(route.projectId) + '/poam.json');
        if (rawPOAM) { cachedPOAM = transformPOAM(rawPOAM); }

        var projectsData = await fetchJSON('/projects.json');
        var projects = (projectsData || SAMPLE_PROJECTS).projects || [];
        var project = null;
        for (var i = 0; i < projects.length; i++) {
            if (projects[i].id === route.projectId) { project = projects[i]; break; }
        }
        cachedProject = project;

        var meta = indexData.metadata || {};
        var gate = indexData.gate || {};

        app.innerHTML =
            renderDetailHeader(meta, gate, project) +
            '<div class="split-layout">' +
                '<nav class="left-panel" id="left-panel">' +
                    renderLeftPanel(indexData) +
                '</nav>' +
                '<div class="right-panel" id="right-panel"></div>' +
            '</div>';

        wireHeaderNav();
        wireLeftPanelNav();
        selectView('overview');
    }

    window.scrollTo(0, 0);
}

function wireHeaderNav() {
    var title = document.querySelector('.site-title');
    if (title) {
        title.addEventListener('click', function() { navigateTo('#/'); });
        title.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigateTo('#/'); }
        });
    }

    var backBtn = document.getElementById('back-btn');
    if (backBtn) {
        backBtn.addEventListener('click', function() { navigateTo('#/'); });
    }
}

// ---- Bootstrap ----

window.addEventListener('hashchange', handleRoute);

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', handleRoute);
} else {
    handleRoute();
}
