# Step 2: parallel-pipeline

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `orchestrator/rmf/pipeline.py` — 현재 파이프라인 (이번 step에서 대폭 수정)
- `orchestrator/assessor/bedrock_client.py` — step0에서 추가된 `stream_with_cache()` 확인
- `orchestrator/rmf/models.py` — SP 800-30 데이터 모델
- `orchestrator/rmf/static_pipeline.py` — `StaticRiskAssessmentPipeline.build_assessment()` (per-finding fallback에 사용)
- step1에서 추가된 프롬프트 빌더 함수 (`build_per_finding_prompts`, `build_summary_prompts`)

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`orchestrator/rmf/pipeline.py`의 `RiskAssessmentPipeline._step3_assess()`를 리팩터링한다. 기존 단일 `_ai_assess()` 호출을 **parallel per-finding + summary** 구조로 교체.

### 새 아키텍처

```
_step3_assess(filtered)
  ├── _assess_findings_parallel(filtered)  # ThreadPoolExecutor, 5 concurrent calls
  │     ├── _assess_single_finding(finding_0, ...)  # stream_with_cache()
  │     ├── _assess_single_finding(finding_1, ...)  # stream_with_cache()
  │     ├── _assess_single_finding(finding_2, ...)  # stream_with_cache()
  │     ├── _assess_single_finding(finding_3, ...)  # stream_with_cache()
  │     └── _assess_single_finding(finding_4, ...)  # stream_with_cache()
  │           (실패 시 → _static_assess_single_finding(finding) 로 fallback)
  │
  └── _synthesize_summary(per_finding_results)  # stream_with_cache(), single call
        (실패 시 → 정적 executive summary)
```

### 시그니처

```python
def _assess_findings_parallel(
    self,
    filtered: dict[str, Any],
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> list[dict[str, Any]]:
    """Assess each finding in parallel using ThreadPoolExecutor.

    Args:
        filtered: step2 output (selected_findings, relevant_controls, etc.)
        progress_callback: optional (completed, total, finding_id) → None for CLI progress

    Returns:
        list of per-finding assessment dicts (order matches selected_findings)
    """

def _assess_single_finding(
    self,
    finding: dict[str, Any],
    controls: list[dict[str, Any]],
    epss_data: dict[str, Any] | None,
    manifest: ProductManifest,
    finding_index: int,
) -> dict[str, Any]:
    """Assess one finding via Bedrock stream_with_cache().

    On failure, falls back to static assessment for this finding only.
    """

def _synthesize_summary(
    self,
    per_finding_results: list[dict[str, Any]],
    manifest: ProductManifest,
    total_findings: int,
    severity_counts: dict[str, int],
) -> dict[str, Any]:
    """Generate executive summary + cross-signal insights from all per-finding results."""

def _static_assess_single_finding(
    self,
    finding: dict[str, Any],
    manifest: ProductManifest,
    finding_index: int,
) -> dict[str, Any]:
    """Deterministic single-finding assessment (fallback)."""
```

### 핵심 규칙

1. **ThreadPoolExecutor**: `concurrent.futures.ThreadPoolExecutor(max_workers=5)`. `as_completed()`로 완료 순서대로 `progress_callback` 호출.
2. **prompt caching**: `stream_with_cache(system_prompt, user_prompt)`로 호출. system prompt는 5개 finding 호출에서 동일 (architecture + methodology). 첫 호출에서 cache creation, 2-5 호출에서 cache read.
3. **per-finding fallback**: `_assess_single_finding()` 내부에서 예외 발생 시 `_static_assess_single_finding()`으로 대체. 로그 남기고 계속 진행.
4. **mixed-mode**: per-finding 결과에 `"mode": "ai"` 또는 `"mode": "static"` 태그. 최종 report의 `mode` 필드: 전부 AI → `"ai"`, 전부 static → `"static"`, 섞임 → `"hybrid"`.
5. **SP80030Report.mode 확장**: `models.py`에서 mode 필드의 docstring을 `"ai" | "static" | "hybrid"`로 업데이트.
6. **_build_report() 수정**: per-finding 결과 리스트 + summary 결과를 받아 `SP80030Report`를 조립. threat_sources/events/etc.는 per-finding 결과에서 수집, executive_summary/recommendations는 summary에서.
7. **기존 _ai_assess() 제거**: 새 구조로 완전 대체. 기존 모놀리식 프롬프트(`SP800_30_ASSESSMENT_PROMPT`)는 호출하지 않으나 삭제하지 않는다.
8. **ADR-004 준수**: AI는 advisory only. risk_score와 risk_level은 AI가 산출하지만, gate 결정은 여전히 ThresholdEvaluator가 한다.

### 테스트 (TDD)

`tests/unit/test_parallel_pipeline.py`:

1. **test_parallel_5_findings_all_succeed**: 5개 mock AI 응답 → 5개 AI 결과 + summary, mode="ai"
2. **test_parallel_2_of_5_fail_fallback**: 2개 실패 → 3 AI + 2 static, mode="hybrid"
3. **test_parallel_all_fail_full_static**: 5개 모두 실패 → 5 static + static summary, mode="static"
4. **test_parallel_progress_callback**: progress_callback이 5번 호출되는지 확인
5. **test_parallel_no_bedrock_uses_static**: bedrock_client=None → 전부 static
6. **test_summary_receives_all_narratives**: summary 프롬프트에 5개 narrative가 포함되는지 확인
7. **test_report_mode_hybrid**: mixed 결과에서 SP80030Report.mode == "hybrid" 확인

mock 전략: `BedrockClient.stream_with_cache`를 mock. 반환값은 per-finding JSON 문자열. 특정 호출에서 예외를 raise하여 fallback 테스트.

## Acceptance Criteria

```bash
python -m pytest tests/unit/test_parallel_pipeline.py -v  # 7 tests pass
python -m pytest tests/unit/ -v --tb=short                # 기존 테스트 깨지지 않음
make lint                                                  # ruff + mypy 통과
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - `ThreadPoolExecutor`가 `max_workers=5`인가?
   - per-finding fallback이 해당 finding만 static으로 대체하고, 나머지 AI 결과는 보존하는가?
   - `progress_callback`이 `as_completed()` 루프에서 호출되는가?
   - AI가 gate 결정을 하지 않는가? (ADR-004)
   - `stream_with_cache()`를 사용하는가? (`invoke()` 아님)
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다.

## 금지사항

- `asyncio`를 사용하지 마라. 이유: 프로젝트는 동기 Python이다. `ThreadPoolExecutor`만 사용한다.
- `FILTER_PROMPT`를 수정하지 마라. 이유: Step 2 (Haiku 필터)는 변경 대상이 아니다.
- AI 결과로 gate 결정을 하지 마라. 이유: ADR-004 위반이다.
- `SP800_30_ASSESSMENT_PROMPT`를 삭제하지 마라. 이유: 참조용으로 보존한다.
- 기존 테스트를 깨뜨리지 마라.
