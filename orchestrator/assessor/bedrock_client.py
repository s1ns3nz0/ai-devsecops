"""Bedrock InvokeModel API wrapper — isolated for testability."""

from __future__ import annotations

import json
from typing import Any


class BedrockInvocationError(Exception):
    """Raised when Bedrock InvokeModel API call fails."""


class BedrockClient:
    """boto3 bedrock-runtime wrapper.

    Separated from BedrockRiskAssessor for easy mocking in tests.
    Uses Claude Messages API format via InvokeModel (ADR-002: no MCP, no Bedrock Agent).
    """

    def __init__(self, model_id: str, region: str) -> None:
        self._model_id = model_id
        self._region = region
        self._client = self._create_client()

    def _create_client(self) -> Any:
        """Lazy boto3 client creation."""
        import boto3

        return boto3.client(
            "bedrock-runtime",
            region_name=self._region,
        )

    def invoke(self, prompt: str, max_tokens: int = 4096) -> str:
        """Invoke Bedrock InvokeModel API with Claude Messages format.

        Returns the text content of the AI response.
        Raises BedrockInvocationError on any failure.
        Timeout: 30 seconds (via boto3 config).
        """
        try:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "user", "content": prompt},
                ],
            })

            response = self._client.invoke_model(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )

            response_body = json.loads(response["body"].read())
            return response_body["content"][0]["text"]  # type: ignore[no-any-return]

        except Exception as exc:
            raise BedrockInvocationError(f"Bedrock invocation failed: {exc}") from exc
