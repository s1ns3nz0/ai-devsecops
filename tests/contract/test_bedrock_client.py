"""Contract tests for BedrockClient — uses recorded fixtures, no real API calls."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


class TestInvokeReturnsValidCategorizeResponse:
    def test_invoke_returns_valid_categorize_response(self) -> None:
        raw = (FIXTURES / "bedrock_categorize_response.json").read_text()
        data = json.loads(raw)

        assert "tier" in data
        assert data["tier"] in ("low", "medium", "high", "critical")
        assert "reasoning" in data
        assert isinstance(data["reasoning"], str)
        assert len(data["reasoning"]) > 0
        assert "threat_profile" in data
        assert isinstance(data["threat_profile"], list)


class TestInvokeReturnsValidAssessResponse:
    def test_invoke_returns_valid_assess_response(self) -> None:
        raw = (FIXTURES / "bedrock_assess_response.json").read_text()
        data = json.loads(raw)

        assert "narrative" in data
        assert isinstance(data["narrative"], str)
        assert len(data["narrative"]) > 20
        assert "cross_signal_insights" in data
        assert isinstance(data["cross_signal_insights"], list)
        assert "recommendations" in data
        assert isinstance(data["recommendations"], list)
        assert "gate_recommendation" in data
        assert data["gate_recommendation"] in ("proceed", "hold_for_review", "block")
