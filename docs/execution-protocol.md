# Safeguard Execution Protocol

## Purpose

This document defines the shared execution protocol principles that Safeguard, Cabal, and MemoryX should follow while they are developed separately.

Safeguard is the lower trusted execution layer. Cabal is expected to plan and produce contracts. MemoryX is expected to store contract grounds and receipts as durable evidence.

The protocol exists to prevent each separate project from inventing incompatible task, evidence, audit, and receipt structures. The combined Cabal + MemoryX + Safeguard system is a separate future integration target; this document only defines common principles and wire shapes, not a merged implementation, shared runtime, or shared codebase.

## Transparency Rule

The protocol is not normal model context.

Coding models should continue to use native Codex workflows. Safeguard hooks and policy layers enforce contracts transparently. Model-facing output should be limited to normal success, concise failure reasons, or explicit user-requested audit summaries.

The protocol must remain auditable and inspectable when explicitly requested, but it must not be injected into ordinary model context as recurring operational burden.

## System Loop

```text
plan -> execute -> verify -> learn -> replan
```

Separate-project responsibilities:

- Cabal: plan, decompose work, generate `ExecutionContract`.
- Safeguard: execute or supervise execution, enforce contract, verify result, emit `ExecutionReceipt`.
- MemoryX: store the contract basis, evidence, receipts, and learned state.

## ExecutionContract v0.1

An `ExecutionContract` is the authority Safeguard uses to decide what an agent may do.

```yaml
execution_contract:
  schema_version: "0.1"
  contract_id: "task-1842"
  parent_contract_id: null
  created_at: "2026-07-03T00:00:00Z"
  expires_at: "2026-07-03T01:00:00Z"
  issuer:
    system: "cabal"
    run_id: "run-id"
  subject:
    agent_id: "agent-id"
    model: "model-id"
  workspace:
    root: "."
    allowed_roots:
      - "."
  capabilities:
    - tool: "apply_patch"
      operation: "modify"
      resources:
        - "crates/example/src/lib.rs"
      constraints:
        max_files_changed: 1
        allowed_write_roots:
          - "crates/example/src/**"
    - tool: "Bash"
      operation: "execute"
      resources:
        - "cargo test -p example"
      constraints:
        network: false
  denied_resources:
    - ".git/**"
    - ".safeguard/**"
  expected_changes:
    files:
      - path: "crates/example/src/lib.rs"
        operation: "modify"
        before_digest: "optional"
        expected_diff_digest: "optional"
        requirement: "required"
  required_validations:
    - command: "cargo fmt --check"
    - command: "cargo test -p example"
  invariants:
    - "no_unclaimed_file_changes"
    - "no_digest_mismatch"
```

### Contract Semantics

- `contract_id` is the stable correlation key across Safeguard, Cabal, and MemoryX.
- `capabilities` define allowed operations. Anything not allowed is denied by default.
- Contracts are validated before authorization as `ParsedContract -> VerifiedContract -> ActiveContract`.
- Schema v0.1 validators currently require a supported `schema_version`, non-expired `expires_at`, trusted local issuer policy, matching workspace root, allowed roots inside the workspace, and known capability constraints.
- Unknown mandatory capability constraints are denied by default. Current known constraint keys are `max_files_changed`, `network`, `allowed_write_roots`, and `validation_timeout_seconds`.
- In schema v0.1, `capabilities[].operation` is accepted as either a tool action such as `invoke` or a resource operation such as `add`, `modify`, or `delete`. Safeguard treats `tool: apply_patch` as the patch invocation authority even when Codex delivered it through a shell-wrapped `apply_patch` hook event.
- `denied_resources` override allowed capabilities.
- `expected_changes` bind the intended result to files, operations, and optional digests.
- `expected_changes.files[].requirement` defaults to `required`. Required expected changes must be observed before acceptance. Optional expected changes are allowed but not mandatory.
- `required_validations` define checks that must be attached to the receipt before acceptance.
- `invariants` define acceptance conditions.

## ExecutionReceipt v0.1

An `ExecutionReceipt` is Safeguard's evidence object for one contract execution.

```yaml
execution_receipt:
  schema_version: "0.1"
  contract_id: "task-1842"
  receipt_id: "receipt-id"
  status: "accepted"
  started_at: "2026-07-03T00:10:00Z"
  completed_at: "2026-07-03T00:11:00Z"
  executor:
    system: "safeguard"
    version: "1.2.0"
  observed_operations:
    - tool: "apply_patch"
      operation: "modify"
      path: "crates/example/src/lib.rs"
  changed_files:
    - path: "crates/example/src/lib.rs"
      operation: "modify"
      before_digest: "digest"
      after_digest: "digest"
      diff_digest: "digest"
  validations:
    - command: "cargo fmt --check"
      status: "passed"
    - command: "cargo test -p example"
      status: "passed"
  policy_violations: []
  invariants:
    - name: "no_unclaimed_file_changes"
      status: "passed"
  receipt_hash: "digest"
  previous_receipt_hash: "digest-or-null"
  signature: null
```

Receipt status values:

- `prepared`: execution is durably prepared but not finally accepted;
- `accepted`: final success after transaction completion;
- `rejected`: denied or rejected execution;
- `partial`: incomplete state requiring quarantine/recovery handling;
- `rolled_back`: rollback completed.

`accepted` is final-only. Safeguard must not emit an accepted receipt before transaction completion succeeds.

### Receipt Semantics

- `status` is one of `accepted`, `rejected`, `partial`, or `rolled_back`.
- `observed_operations` records what actually happened.
- `changed_files` records before/after/diff digests.
- `validations` records required check results.
- `policy_violations` records denied or out-of-contract actions.
- `receipt_hash` covers the canonical receipt body.
- `previous_receipt_hash` allows hash-chain continuity.
- `signature` is optional for later trusted-release or team deployments.

## MemoryX Evidence Record v0.1

MemoryX should not need to store huge raw logs. It should store compact evidence anchors.

```yaml
memoryx_evidence:
  schema_version: "0.1"
  contract_id: "task-1842"
  receipt_id: "receipt-id"
  claim: "Task task-1842 was accepted by Safeguard"
  basis:
    contract_hash: "digest"
    receipt_hash: "digest"
    source_paths:
      - ".safeguard/receipts/receipt-id.json"
  summary:
    changed_files_count: 1
    validations_passed: 2
    policy_violations_count: 0
```

## Compatibility Rules

- Additive schema changes must bump minor version.
- Breaking schema changes must bump major version.
- Unknown fields should be ignored by readers unless policy explicitly requires strict mode.
- Safeguard must preserve enough raw local evidence to regenerate receipt hashes.
- Cabal must not assume a receipt is accepted unless `status: accepted` and required invariants passed.
- MemoryX stores evidence summaries and hashes; it does not become the execution authority.

## Current Implementation Mapping

Implemented now:

- transparent plugin hook layer;
- short MCP fallback tools backed by the same transaction engine for `sg_apply`;
- internal audit JSONL;
- initial transaction crate with locks, digest CAS, rollback snapshots, recovery candidate scan, and `ExecutionContract` target mapping;
- hook-side implicit `ExecutionContract` binding for native `apply_patch`;
- optional explicit `ExecutionContract` loading through `SAFEGUARD_CONTRACT_PATH`;
- hook-side capability, expected-file, and denied-resource enforcement for explicit contracts;
- persistent transaction lifecycle across separate `PreToolUse` and `PostToolUse` hook processes;
- hook-side `ExecutionReceipt v0.1` emission for guarded native edits;
- receipt-level expected add/modify/delete result verification;
- exact expected after-content digest verification for standard `apply_patch` edits;
- patch section digest recorded as `diff_digest` / `expected_diff_digest` evidence for native patch edits;
- required validation command execution for explicit contracts; validation failure prevents acceptance and triggers rollback;
- append-only receipt files with monotonic sequence ids;
- serialized receipt chain-head updates through a local chain lock, with continuity through `previous_receipt_hash`;
- hard denial of native patch targets inside `.safeguard/**`;
- local MemoryX-shaped evidence summary export from contract and receipt hashes;
- explicit recovery CLI for listing interrupted transactions and rolling them back with recovery receipts.

Next Safeguard implementation steps:

- run release packaging and plugin reinstall validation before the next public release.
