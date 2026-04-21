# Step 4: defectdojo-compose

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ARCHITECTURE.md` — "Evidence Path" 섹션
- `/docs/ADR.md` — ADR-008 (Evidence는 generated artifact)
- `/docs/architecture-design.md` — DefectDojo 관련 섹션

## 작업

### 4-1. Docker Compose 파일

`docker-compose.yml`을 프로젝트 루트에 생성한다:

```yaml
# DefectDojo — Finding triage and evidence source of truth
# Usage: docker compose up -d
# First run takes ~5 minutes for database initialization.
```

DefectDojo 구성:
- `defectdojo-django` — 웹 앱 (pinned version: `defectdojo/defectdojo-django:2.38.1`)
- `defectdojo-nginx` — reverse proxy
- `defectdojo-celery-beat` — task scheduler
- `defectdojo-celery-worker` — async worker
- `defectdojo-postgres` — database (persistent volume)
- `defectdojo-redis` — message broker

포트: `127.0.0.1:8080:8080` (localhost only)

환경변수:
- `DD_ADMIN_USER=admin`
- `DD_ADMIN_PASSWORD=admin` (dev only)
- `DD_ADMIN_MAIL=admin@example.com`
- `DD_DATABASE_URL=postgresql://defectdojo:defectdojo@postgres:5432/defectdojo`

Volume: `defectdojo-postgres-data` (persistent)

### 4-2. Makefile 업데이트

기존 Makefile에 Docker 관련 target 추가:

```makefile
docker-up:
	docker compose up -d
	@echo "DefectDojo starting at http://127.0.0.1:8080 (admin/admin)"
	@echo "First run takes ~5 minutes for initialization."

docker-down:
	docker compose down

docker-reset:
	docker compose down -v
	@echo "All data deleted."

demo-docker: docker-up
	@echo "Waiting for DefectDojo to be ready..."
	@sleep 30
	python -m orchestrator demo tests/fixtures/sample-app --product payment-api
```

### 4-3. 테스트

Docker Compose 파일의 구문 검증:

`tests/unit/test_docker_compose.py`:
- `test_compose_file_valid_yaml` — docker-compose.yml이 유효한 YAML
- `test_compose_has_required_services` — 6개 서비스 정의 확인
- `test_postgres_has_persistent_volume` — postgres 볼륨 존재
- `test_ports_bind_to_localhost` — 포트가 127.0.0.1에 바인딩

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

Docker Compose 실행은 AC에 포함하지 않음 (Docker가 설치되어 있지 않을 수 있음).

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `docker-compose.yml`이 존재하고 유효한 YAML인지 확인한다.
3. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- Docker Compose를 unit 테스트에서 실행하지 마라.
- DefectDojo 버전을 `:latest`로 지정하지 마라. 이유: 재현 가능성 (Red Team RT-12).
- 0.0.0.0 포트 바인딩을 사용하지 마라. 127.0.0.1만 (Red Team RT-17).
- production 비밀번호를 사용하지 마라. dev 전용 (`admin/admin`).
