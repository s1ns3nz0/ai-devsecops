"""Bedrock InvokeModel API wrapper — isolated for testability."""

from __future__ import annotations

import json
import logging
import time
from typing import Any


logger = logging.getLogger(__name__)


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

            t0 = time.monotonic()
            response = self._client.invoke_model(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            elapsed = time.monotonic() - t0

            response_body = json.loads(response["body"].read())

            logger.info(
                "Bedrock API call completed in %.2fs (model=%s)",
                elapsed,
                self._model_id,
            )

            # Log token usage if present in response
            usage = response_body.get("usage")
            if usage:
                logger.info(
                    "Token usage — input: %s, output: %s",
                    usage.get("input_tokens", "?"),
                    usage.get("output_tokens", "?"),
                )

            return response_body["content"][0]["text"]  # type: ignore[no-any-return]

        except Exception as exc:
            err_msg = str(exc)
            if "AccessDeniedException" in err_msg or "not authorized" in err_msg.lower():
                raise BedrockInvocationError(
                    f"Model access not enabled — go to AWS Console → Bedrock → Model access "
                    f"and enable {self._model_id} in {self._region}. Original error: {exc}"
                ) from exc
            if "ValidationException" in err_msg and "model" in err_msg.lower():
                raise BedrockInvocationError(
                    f"Invalid model ID '{self._model_id}'. Check BEDROCK_MODEL_ID "
                    f"environment variable. Original error: {exc}"
                ) from exc
            raise BedrockInvocationError(f"Bedrock invocation failed: {exc}") from exc
