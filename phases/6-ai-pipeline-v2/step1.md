# Step 1: per-finding-prompts

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `orchestrator/rmf/pipeline.py` — 현재 프롬프트 템플릿 (`FILTER_PROMPT`, `SP800_30_ASSESSMENT_PROMPT`)
- `orchestrator/rmf/models.py` — SP 800-30 데이터 모델 (ThreatSource, ThreatEvent, etc.)
- `orchestrator/assessor/prompts.py` — 기존 프롬프트 모듈 (architecture_context, mission_context 포매터)

이전 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`orchestrator/rmf/prompts.py` 또는 `orchestrator/rmf/pipeline.py` 상단에 두 개의 새 프롬프트 템플릿을 추가한다. 기존 `FILTER_PROMPT`는 유지하고, `SP800_30_ASSESSMENT_PROMPT`는 두 개로 교체한다.

### 1. `PER_FINDING_ASSESSMENT_PROMPT` — 개별 finding 분석용

AI가 단일 finding에 대해 SP 800-30 전체 분석을 수행하는 프롬프트.

**System prompt** (캐시 대상 — 모든 finding 호출에서 동일):
- SP 800-30 Rev 1 방법론 설명
- 제품 아키텍처 컨텍스트 (product name, description, cloud, jurisdiction, CIA levels)
- JSON 응답 스키마 (per-finding 단위)

**User prompt** (finding마다 다름):
- 단일 finding 상세 (source, rule_id, severity, file, line, message, control_ids, package info)
- 해당 finding에 매핑된 컨트롤 목록
- 해당 finding의 EPSS 데이터 (있으면)

**응답 스키마** (per-finding — 기존 모놀리식의 배열이 아닌 단일 객체):
```json
{
  "threat_source": {
    "id": "TS-XXX-NNN",
    "type": "adversarial|accidental|structural|environmental",
    "name": "...",
    "capability": "very-low|low|moderate|high|very-high",
    "intent": "...",
    "targeting": "..."
  },
  "threat_event": {
    "id": "TE-NNN",
    "description": "...",
    "source_id": "TS-XXX-NNN",
    "mitre_technique": "TNNNN",
    "relevance": "confirmed|expected|predicted|possible",
    "cve_id": "",
    "target_component": "..."
  },
  "likelihood": {
    "initiation_likelihood": "...",
    "impact_likelihood": "...",
    "overall_likelihood": "...",
    "epss_score": null,
    "predisposing_conditions": ["..."],
    "evidence": "..."
  },
  "impact": {
    "impact_type": "harm to operations|harm to assets|harm to individuals",
    "cia_impact": {"confidentiality": "...", "integrity": "...", "availability": "..."},
    "severity": "...",
    "compliance_impact": ["CONTROL-ID"],
    "business_impact": "...",
    "evidence": "..."
  },
  "risk_determination": {
    "threat_event_id": "TE-NNN",
    "likelihood": "...",
    "impact": "...",
    "risk_level": "...",
    "risk_score": 0.0
  },
  "risk_response": {
    "risk_determination_id": "TE-NNN",
    "response_type": "accept|avoid|mitigate|share|transfer",
    "description": "...",
    "milestones": ["..."],
    "deadline": "YYYY-MM-DD",
    "responsible": "..."
  },
  "narrative": "2-sentence summary of this finding's risk and recommended action."
}
```

### 2. `SUMMARY_SYNTHESIS_PROMPT` — 종합 요약용

5개 per-finding 결과를 받아 종합 분석을 수행하는 프롬프트.

**System prompt** (캐시 대상):
- SP 800-30 executive summary 작성 지침
- 제품 아키텍처 컨텍스트 (동일)
- 교차 신호 분석 지침: 개별 finding 간의 공격 체인, 복합 위험, 상관관계를 식별하라

**User prompt**:
- 5개 per-finding 결과 JSON (narrative 포함)
- 전체 finding 통계 (total, by severity)

**응답 스키마**:
```json
{
  "executive_summary": "2-3 paragraph narrative for decision-makers",
  "cross_signal_insights": [
    "Finding A + Finding B together create an escalation path...",
    "..."
  ],
  "overall_risk_posture": "very-low|low|moderate|high|very-high",
  "recommendations": ["prioritized action items"]
}
```

### 핵심 규칙

1. **프롬프트 분리**: system prompt (캐시 대상)과 user prompt (가변)을 명확히 분리한다. `stream_with_cache(system_prompt, user_prompt)` 호출에 직접 대응.
2. **ID 채번**: per-finding에서 `TE-{index+1:03d}` 형식. index는 0-based finding 순번. 예: TE-001, TE-002.
3. **기존 FILTER_PROMPT 유지**: Haiku 필터링 프롬프트는 변경하지 않는다.
4. **기존 SP800_30_ASSESSMENT_PROMPT 유지**: 삭제하지 않는다. 새 프롬프트를 추가만 한다. 구 프롬프트는 step2에서 대체 연결한다.

### 테스트 (TDD)

`tests/unit/test_per_finding_prompts.py`:

1. **test_per_finding_system_prompt_contains_methodology**: system prompt에 "SP 800-30" 포함 확인
2. **test_per_finding_system_prompt_contains_architecture**: 제품명, CIA levels 포함 확인
3. **test_per_finding_user_prompt_contains_finding**: finding의 rule_id, severity, file 포함 확인
4. **test_per_finding_user_prompt_contains_epss**: EPSS score 포함 확인
5. **test_summary_system_prompt_contains_cross_signal**: "cross-signal" 또는 "correlation" 키워드 포함 확인
6. **test_summary_user_prompt_contains_all_narratives**: 5개 narrative가 모두 포함되었는지 확인

프롬프트 빌더 함수를 만들어라:
```python
def build_per_finding_prompts(
    manifest: ProductManifest,
    finding: dict[str, Any],
    controls: list[dict[str, Any]],
    epss_data: dict[str, Any] | None,
) -> tuple[str, str]:  # (system_prompt, user_prompt)

def build_summary_prompts(
    manifest: ProductManifest,
    per_finding_results: list[dict[str, Any]],
    total_findings: int,
    severity_counts: dict[str, int],
) -> tuple[str, str]:  # (system_prompt, user_prompt)
```

## Acceptance Criteria

```bash
python -m pytest tests/unit/test_per_finding_prompts.py -v  # 6 tests pass
python -m pytest tests/unit/ -v --tb=short                  # 기존 테스트 깨지지 않음
make lint                                                    # ruff + mypy 통과
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - system prompt와 user prompt이 명확히 분리되어 캐싱에 적합한가?
   - per-finding 응답 스키마가 `orchestrator/rmf/models.py`의 dataclass들과 1:1 대응하는가?
   - 기존 `FILTER_PROMPT`와 `SP800_30_ASSESSMENT_PROMPT`가 변경되지 않았는가?
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다.

## 금지사항

- 기존 `FILTER_PROMPT`를 수정하지 마라. 이유: Haiku 필터 호출이 사용 중이다.
- 기존 `SP800_30_ASSESSMENT_PROMPT`를 삭제하지 마라. 이유: step2에서 교체 연결한다.
- 프롬프트에 timestamp나 난수를 넣지 마라. 이유: prompt caching이 invalidate된다.
- 기존 테스트를 깨뜨리지 마라.
