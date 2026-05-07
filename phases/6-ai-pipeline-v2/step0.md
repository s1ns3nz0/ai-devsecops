# Step 0: bedrock-streaming

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `orchestrator/assessor/bedrock_client.py` — 현재 BedrockClient 구현 (invoke, invoke_with_cache)
- `tests/unit/test_bedrock_client.py` — 기존 테스트 (있으면)

이전 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`orchestrator/assessor/bedrock_client.py`의 `BedrockClient` 클래스에 `stream_with_cache()` 메서드를 추가한다.

### 시그니처

```python
def stream_with_cache(
    self,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 4096,
) -> str:
    """Invoke Bedrock WITH prompt caching AND streaming.

    Uses invoke_model_with_response_stream() instead of invoke_model().
    Accumulates response chunks internally and returns complete text.

    No read timeout risk — first byte arrives in ~2s,
    chunks stream until completion.
    """
```

### 핵심 규칙

1. **boto3 API**: `self._client.invoke_model_with_response_stream()` 사용. 파라미터는 `invoke_with_cache()`와 동일한 body (anthropic_version, max_tokens, system with cache_control, messages).
2. **스트리밍 파싱**: response["body"]는 `EventStream` 객체다. 이터레이션하면 각 chunk에서 `chunk["bytes"]`를 읽을 수 있다. 각 chunk를 JSON 파싱하면 `{"type": "content_block_delta", "delta": {"text": "..."}}` 형태다. `delta.text`를 누적하여 최종 문자열을 반환한다.
3. **토큰 로깅**: 스트리밍 완료 후 `message_stop` 이벤트에서 usage 정보를 추출하여 `_log_response()`를 호출한다. 스트리밍에서는 `message_delta` 이벤트의 `usage.output_tokens`와 `amazon-bedrock-invocationMetrics` 헤더에서 토큰 정보를 얻을 수 있다.
4. **rate limit**: 기존 `_check_rate_limit()`을 호출 시작 시 실행한다.
5. **에러 처리**: 기존 패턴 유지 — `BedrockInvocationError`, `BedrockRateLimitError`는 재raise, 나머지는 `_wrap_exception()`으로 변환.
6. **기존 메서드 변경 금지**: `invoke()`와 `invoke_with_cache()`는 그대로 둔다. Haiku 필터 호출은 여전히 `invoke()`를 사용한다.

### 테스트 (TDD)

테스트를 먼저 작성한다. `tests/unit/test_bedrock_streaming.py`:

1. **test_stream_with_cache_accumulates_chunks**: mock EventStream이 3개 chunk를 반환 → 누적된 전체 텍스트가 반환되는지 확인
2. **test_stream_with_cache_rate_limit**: rate limit 초과 시 `BedrockRateLimitError` 발생 확인
3. **test_stream_with_cache_uses_cache_control**: body에 `cache_control: {"type": "ephemeral"}` 포함 확인
4. **test_stream_with_cache_wraps_exceptions**: boto3 예외 → `BedrockInvocationError` 변환 확인
5. **test_stream_with_cache_logs_timing**: elapsed time이 로깅되는지 확인

mock 전략: `self._client.invoke_model_with_response_stream`을 mock한다. 반환값은 `{"body": <iterable of chunks>}` 형태. 각 chunk는 `{"chunk": {"bytes": b'{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello "}}'}}`.

## Acceptance Criteria

```bash
python -m pytest tests/unit/test_bedrock_streaming.py -v  # 5 tests pass
python -m pytest tests/unit/ -v --tb=short                # 기존 테스트 깨지지 않음
make lint                                                  # ruff + mypy 통과
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - `invoke()`와 `invoke_with_cache()`가 변경되지 않았는가?
   - `stream_with_cache()`가 `invoke_with_cache()`와 동일한 body를 전송하는가?
   - rate limit이 호출 시작 시 체크되는가?
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다:
   - 성공 → `"status": "completed"`, `"summary": "산출물 한 줄 요약"`
   - 수정 3회 시도 후에도 실패 → `"status": "error"`, `"error_message": "구체적 에러 내용"`
   - 사용자 개입 필요 → `"status": "blocked"`, `"blocked_reason": "구체적 사유"` 후 즉시 중단

## 금지사항

- `invoke()` 또는 `invoke_with_cache()` 메서드를 수정하지 마라. 이유: Haiku 필터와 기존 assess 커맨드가 이 메서드들을 사용한다.
- `asyncio`나 `aioboto3`를 사용하지 마라. 이유: 프로젝트는 동기 Python이다.
- 라이브 Bedrock 호출을 테스트에 넣지 마라. 이유: CI에서 AWS 자격 증명이 없다. 모든 테스트는 mock 기반이어야 한다.
- 기존 테스트를 깨뜨리지 마라.
