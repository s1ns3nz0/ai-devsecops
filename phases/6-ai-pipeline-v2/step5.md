# Step 5: ci-s3-upload

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- `.github/workflows/security-gate.yml` — 현재 security gate 워크플로우
- `.github/workflows/ci.yml` — CI 워크플로우 (참조)
- `.github/workflows/build-dast.yml` — Build+DAST 워크플로우 (참조)

이전 step에서 만들어진 코드를 꼼꼼히 읽고, 설계 의도를 이해한 뒤 작업하라.

## 작업

`.github/workflows/security-gate.yml`에 dashboard JSON을 S3에 업로드하는 step을 추가한다.

### S3 구조

```
s3://{BUCKET}/
  latest/                          ← 최신 결과 (CloudFront가 서빙)
    index.json
    sp800-30.json
    sar.json
    poam.json
    authorization.json
  runs/                            ← 히스토리
    2026-05-04T12:00:00Z/
      index.json
      sp800-30.json
      ...
    2026-05-03T09:30:00Z/
      ...
  runs/index.json                  ← 실행 목록 (dashboard timeline용)
```

### 워크플로우 변경

`security-gate.yml`에 아래 step들을 추가:

#### 1. AWS OIDC 인증 (이미 있으면 재사용)

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-arn: ${{ secrets.AWS_ROLE_ARN }}
    aws-region: ap-northeast-1
```

#### 2. Dashboard upload

```yaml
- name: Upload dashboard to S3
  if: always()  # gate 결과와 무관하게 항상 업로드
  env:
    DASHBOARD_BUCKET: ${{ secrets.DASHBOARD_BUCKET }}
  run: |
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Upload timestamped run
    aws s3 sync output/dashboard/ "s3://${DASHBOARD_BUCKET}/runs/${TIMESTAMP}/" \
      --cache-control "public, max-age=31536000, immutable"

    # Update latest
    aws s3 sync output/dashboard/ "s3://${DASHBOARD_BUCKET}/latest/" \
      --cache-control "public, max-age=60"

    # Update runs index (list all runs for timeline)
    aws s3api list-objects-v2 \
      --bucket "${DASHBOARD_BUCKET}" \
      --prefix "runs/" \
      --delimiter "/" \
      --query "CommonPrefixes[].Prefix" \
      --output json | python3 -c "
    import sys, json
    prefixes = json.load(sys.stdin) or []
    runs = [p.replace('runs/', '').rstrip('/') for p in prefixes if p != 'runs/']
    runs.sort(reverse=True)
    json.dump({'runs': runs[:100], 'total': len(runs)}, sys.stdout, indent=2)
    " > /tmp/runs-index.json

    aws s3 cp /tmp/runs-index.json "s3://${DASHBOARD_BUCKET}/runs/index.json" \
      --cache-control "public, max-age=60" \
      --content-type "application/json"

    echo "Dashboard uploaded: s3://${DASHBOARD_BUCKET}/runs/${TIMESTAMP}/"
```

### Cache-Control 전략

| 경로 | Cache-Control | 이유 |
|------|--------------|------|
| `runs/{timestamp}/*` | `max-age=31536000, immutable` | 과거 실행은 절대 변경 안 됨 |
| `latest/*` | `max-age=60` | 새 실행이 올 때마다 교체 |
| `runs/index.json` | `max-age=60` | 새 실행 추가 시 갱신 |

### GitHub Secrets 필요

| Secret | 값 | 용도 |
|--------|-----|------|
| `AWS_ROLE_ARN` | `arn:aws:iam::106760547719:role/github-actions-role` | OIDC federation |
| `DASHBOARD_BUCKET` | (생성 필요) | S3 bucket name |

### 핵심 규칙

1. **`if: always()`**: gate가 DATO여도 dashboard는 업로드한다. DATO 결과 자체가 가치 있는 데이터.
2. **runs/index.json**: S3 list-objects로 실행 목록을 생성하여 별도 DB 없이 타임라인 구현 가능.
3. **CORS**: S3 bucket에 CORS 설정 필요 (CloudFront → S3). 이것은 Terraform에서 설정하므로 이 step에서는 워크플로우만 작성.
4. **실패 허용**: S3 업로드 실패가 워크플로우 전체를 실패시키면 안 된다. `continue-on-error: true` 추가.

### 테스트

이 step은 GitHub Actions 워크플로우 변경이므로 자동화된 단위 테스트 대신 아래를 확인:

1. **YAML 문법 검증**: `python -c "import yaml; yaml.safe_load(open('.github/workflows/security-gate.yml'))"`
2. **기존 step 보존**: 기존 security-gate.yml의 모든 step이 그대로 존재하는지 diff로 확인
3. **secrets 참조 확인**: `AWS_ROLE_ARN`과 `DASHBOARD_BUCKET`이 `${{ secrets.* }}` 형태인지 확인

## Acceptance Criteria

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/security-gate.yml'))"  # YAML 유효
git diff .github/workflows/security-gate.yml | head -100  # 기존 step 보존 확인
grep -c 'DASHBOARD_BUCKET' .github/workflows/security-gate.yml  # >= 1
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - 기존 security-gate.yml step들이 모두 보존되는가?
   - `if: always()`가 설정되어 gate 결과와 무관하게 업로드하는가?
   - `continue-on-error: true`가 설정되어 S3 실패가 워크플로우를 중단시키지 않는가?
   - Cache-Control 헤더가 올바른가? (latest=60s, runs/timestamp=immutable)
3. 결과에 따라 `phases/6-ai-pipeline-v2/index.json`의 해당 step을 업데이트한다.

## 금지사항

- 기존 security-gate.yml step을 삭제하거나 순서를 바꾸지 마라. 이유: 기존 CI/CD 파이프라인을 깨뜨린다.
- AWS access key를 하드코딩하지 마라. 이유: OIDC federation을 사용한다.
- S3 bucket을 생성하지 마라. 이유: Terraform의 책임이다 (별도 phase).
- 기존 테스트를 깨뜨리지 마라.
