"""Application configuration with intentional credential exposure.

This is a FIXTURE for demo/testing purposes only.
All credentials are fake and intentionally detectable by security scanners.
"""

# Vulnerability: Hardcoded AWS credentials (gitleaks detection)
AWS_ACCESS_KEY_ID = "AKIAI44QH8DHBEXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY012"

# Vulnerability: Hardcoded database password
DB_PASSWORD = "prod-payment-db-2026!secret"  # noqa: S105

DATABASE_URL = "postgresql://localhost:5432/payments"
