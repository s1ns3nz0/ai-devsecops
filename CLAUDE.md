# 프로젝트: Compliance-Driven AI Risk Platform

## 기술 스택
- Python 3.11+ (orchestrator, CLI, all integrations)
- YAML + JSON Schema (controls repository, configuration)
- OPA/Rego (policy evaluation — MVP tier only)
- Docker Compose (DefectDojo, Dependency-Track — MVP tier only)
- AWS Bedrock (Claude Sonnet 4.6 — optional, platform works without it)

## 아키텍처 규칙
- CRITICAL: AI는 절대 gate 결정을 하지 않는다. Gate 결정은 YAML threshold + OPA/Rego만 수행. AI는 narrative와 recommendation만 제공.
- CRITICAL: Gate path는 100% 로컬이어야 한다. 외부 서비스(DefectDojo, DT, Bedrock)에 의존하지 않는다. Evidence path만 네트워크를 사용한다.
- CRITICAL: Strategy pattern 준수 — StaticRiskAssessor와 BedrockRiskAssessor는 동일한 인터페이스를 구현한다. Bedrock 없이도 플랫폼이 동작해야 한다.
- 모든 scanner는 로컬 CLI 도구로 실행한다. MCP 서버, Bedrock Agent를 사용하지 않는다.
- Controls Repository는 OSCAL 호환 YAML 파일로 Git에서 관리한다.
- Finding은 항상 Control ID로 태깅한다 — 이것이 전체 플랫폼의 핵심 primary key다.

## 개발 프로세스
- CRITICAL: 새 기능 구현 시 반드시 테스트를 먼저 작성하고, 테스트가 통과하는 구현을 작성할 것 (TDD)
- 커밋 메시지는 conventional commits 형식을 따를 것 (feat:, fix:, docs:, refactor:)
- MVP-0 먼저 구현 (4 scanners, single AI call, JSONL, ~2000 LOC), 이후 MVP로 확장

## 명령어
make setup           # Python 의존성 설치, 도구 체크
make demo            # MVP-0 데모 (fixture 기반)
make demo-full       # Bedrock AI 모드 데모
make demo-docker     # Docker Compose + DefectDojo + DT (MVP tier)
make test            # pytest tests/unit/
make test-contract   # pytest tests/contract/
make lint            # ruff + mypy
