# Step 3: bedrock-live

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md` — ADR-002 (Orchestrator-centric), ADR-004 (AI는 gate하지 않는다)
- `/orchestrator/assessor/interface.py` — RiskAssessor protocol
- `/orchestrator/assessor/bedrock.py` — BedrockRiskAssessor (이미 구현됨)
- `/orchestrator/assessor/bedrock_client.py` — BedrockClient (이미 구현됨)
- `/orchestrator/assessor/prompts.py` — Prompt templates (이미 구현됨)
- `/orchestrator/assessor/static.py` — StaticRiskAssessor (fallback)
- `/orchestrator/cli.py` — get_assessor 함수
- `/.env.example` — Bedrock 설정

## 작업

### 3-1. Bedrock Integration Test Script

`scripts/test_bedrock.py`를 생성한다. 이 스크립트는 실제 Bedrock API를 호출하여 BedrockRiskAssessor가 작동하는지 검증한다.

```python
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
```

스크립트 내용:
- payment-api manifest를 로드하여 `categorize()` 호출
- 3-5개 샘플 finding을 생성하여 `assess()` 호출
- AI narrative, cross-signal insights, recommendations 출력
- Static vs AI 비교 출력
- 결과를 `output/bedrock-test-output.json`에 저장

### 3-2. Bedrock Error Handling 강화

`orchestrator/assessor/bedrock_client.py`를 검토하고 다음을 추가:
- 응답 시간 로깅 (API 호출 전후 timestamp)
- 토큰 사용량 로깅 (응답 JSON에서 `usage` 필드 추출, 있는 경우)
- 명확한 에러 메시지: "Model access not enabled — go to AWS Console → Bedrock → Model access"

### 3-3. Demo 출력에 AI 모드 표시 강화

`orchestrator/demo.py`의 risk assessment 단계에서 AI 모드일 때 추가 정보 출력:

```
[6/8] Risk assessment
      Risk score: 8.4/10
      Mode: AI-augmented (Claude Sonnet 4.6)
      Narrative: "This change introduces significant risk due to..."
      Cross-signal insights:
        - "S3 bucket in same VPC as payment DB..."
        - "CVE-2023-49083 affects cryptography used for..."
      Recommendations:
        - "Enable S3 server-side encryption"
        - "Upgrade cryptography to >= 41.0.6"
```

Static 모드에서는 기존과 동일.

### 3-4. Contract Test 업데이트

`tests/contract/fixtures/` 의 recorded responses를 실제 Bedrock 응답 형식과 일치하도록 검증. 현재 fixture가 올바른 Anthropic Messages API 형식인지 확인:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"tier\": \"critical\", ...}"
    }
  ],
  "stop_reason": "end_turn",
  "usage": {
    "input_tokens": 500,
    "output_tokens": 200
  }
}
```

### 3-5. 테스트

기존 contract test가 통과하는지 확인:

```bash
make test-contract
```

새로운 테스트 추가 없음 (실제 Bedrock 호출은 `scripts/test_bedrock.py`로 수동 검증).

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make test-contract && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `scripts/test_bedrock.py`가 존재하고 실행 가능한지 확인한다.
3. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`
   - Bedrock 접근 불가로 인해 live 테스트 불가 시: `"status": "completed"`, `"summary": "..."` (코드는 완성, live 테스트는 AWS 설정 후)

## 금지사항

- 실제 Bedrock API를 unit/contract 테스트에서 호출하지 마라. `scripts/test_bedrock.py`만 live 호출.
- AI가 risk score를 override하게 하지 마라 (ADR-004).
- `get_assessor()` 의 자동 감지 로직을 변경하지 마라 — BEDROCK_MODEL_ID 환경변수 기반.
