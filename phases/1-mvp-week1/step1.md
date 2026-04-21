# Step 1: rego-policies

## 읽어야 할 파일

- `/CLAUDE.md`
- `/docs/ADR.md` — ADR-004 (AI는 gate하지 않는다)
- `/orchestrator/gate/opa.py` — Step 0에서 생성된 OPA evaluator
- `/controls/baselines/pci-dss-4.0.yaml` — PCI DSS 컨트롤 확인
- `/controls/baselines/fisc-safety.yaml` — FISC 컨트롤 확인
- `/controls/products/payment-api/risk-profile.yaml` — threshold 참조

## 작업

### 1-1. Rego 정책 파일

`rego/gates/` 디렉토리에 Rego 정책을 생성한다. 모든 정책은 `package gates`를 사용한다.

**`rego/gates/pci_critical_findings.rego`** — PCI scope에서 critical finding 차단:
```rego
package gates

deny[msg] {
    input.context.tier == "critical"
    some i
    input.findings[i].severity == "critical"
    some j
    startswith(input.findings[i].control_ids[j], "PCI-DSS")
    msg := sprintf("Critical finding in PCI scope: %s (control: %s)", [input.findings[i].rule_id, input.findings[i].control_ids[j]])
}
```

**`rego/gates/secrets_detection.rego`** — secrets 탐지 시 차단:
```rego
package gates

deny[msg] {
    input.context.secrets_count > 0
    msg := sprintf("Secrets detected: %d findings from gitleaks", [input.context.secrets_count])
}
```

**`rego/gates/high_severity_threshold.rego`** — tier별 high severity 제한:
```rego
package gates

deny[msg] {
    input.context.tier == "critical"
    input.context.findings_count.high > 5
    msg := sprintf("High severity findings (%d) exceed threshold for critical tier (max: 5)", [input.context.findings_count.high])
}

deny[msg] {
    input.context.tier == "high"
    input.context.findings_count.high > 10
    msg := sprintf("High severity findings (%d) exceed threshold for high tier (max: 10)", [input.context.findings_count.high])
}
```

**`rego/gates/iac_network_segmentation.rego`** — 네트워크 세그멘테이션 위반:
```rego
package gates

deny[msg] {
    input.context.tier == "critical"
    some i
    input.findings[i].source == "checkov"
    input.findings[i].rule_id == "CKV_AWS_24"
    msg := sprintf("Network segmentation violation: %s at %s (PCI-DSS-1.3.4)", [input.findings[i].rule_id, input.findings[i].file])
}
```

### 1-2. 테스트

`tests/unit/test_rego_policies.py`:

OPA CLI를 설치하지 않고도 Rego 파일의 구문이 올바른지 검증:
- `test_rego_files_exist` — rego/gates/에 4개 .rego 파일 존재
- `test_rego_files_have_package_gates` — 모든 파일이 `package gates` 선언
- `test_rego_files_have_deny_rule` — 모든 파일에 `deny[msg]` 규칙 존재

OPA가 설치된 환경에서의 integration test (OPA 미설치 시 skip):
- `test_pci_critical_blocks` — critical PCI finding → deny
- `test_secrets_blocks` — secrets_count > 0 → deny
- `test_clean_passes` — finding 없음 → deny 비어있음

## Acceptance Criteria

```bash
cd /Users/s1ns3nz0/ai-devsecops && make test && make lint
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `rego/gates/` 디렉토리에 4개의 .rego 파일이 존재하는지 확인한다.
3. 결과에 따라 `phases/1-mvp-week1/index.json`의 해당 step을 업데이트한다:
   - 성공 시: `"status": "completed"`, `"summary": "한 줄 요약"`

## 금지사항

- Rego 정책에서 외부 데이터(HTTP, 파일)를 로드하지 마라. input만 사용.
- 기존 YAML threshold와 동일한 로직을 Rego로 복제하지 마라. Rego는 YAML이 할 수 없는 복잡한 정책만 담당.
- deny 메시지에 AI 추론 결과를 포함하지 마라.
