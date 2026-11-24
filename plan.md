# Day 2 plan: prioritize, propose, validate, verify

## Goal

Turn a Day 1 finding into a **reviewable, tested remediation proposal**. The demo
should show the original evidence, why the issue matters, the proposed change,
what happened in an isolated build and test, the before-and-after scan, and the
human decision. The target repository is never silently changed, merged, or
deployed.

```text
Day 1 baseline scan
    -> investigate suspicious changes and assess risk
    -> propose a fix with supporting evidence
    -> decide whether an isolated attempt may run automatically
    -> apply the candidate in a sandbox; build and test it
    -> rescan and compare with the baseline
    -> human reviews the exact proposal and validation record
    -> approved change can be handed off for a separate merge or deployment
```

## What Day 1 already gives us

- A CycloneDX SBOM, component graph, dependency paths where available, and a
  commit SHA for the scanned repository.
- Grype vulnerability observations, advisory IDs, severity, and **possible fixed
  versions**. Trivy can add observations from an already-built local image.
- Suspicious npm/lockfile checks, static Docker/CI checks, findings, and scan
  coverage statuses.
- A severity-based initial risk label, generic remediation guidance, a concise
  Markdown report, and complete JSON evidence.

These are inputs, not finished Day 2 decisions. An advisory's fixed version does
not tell us which direct dependency to change, whether the application accepts
that version, whether tests pass, or whether a new risk appears. Current risk
labels do not establish exploitability, reachability, exposure, or provenance.
The current report does not compare a candidate against the baseline.

## Five-person split

| Owner | Day 1 background | Day 2 responsibility | Output and acceptance check |
| --- | --- | --- | --- |
| **Person 1 — contextual risk** | Recon, SBOM, dependency graph | Rank findings using scanner severity plus **observed** application context. Use the graph to identify direct/transitive ownership; add reachability or exposure only when measured. An LLM may explain the ranking from cited evidence and identify questions for review. | `risk_assessment.json`: score, level, evidence references, unknowns, and rationale. The same inputs give a reproducible ranking without the LLM. |
| **Person 2 — remediation planner** | Vulnerability matching | Turn advisory fixed-version hints into candidate actions: upgrade the right direct dependency, update a lockfile, replace/remove a package, update a base image, or propose a mitigation when no fix exists. Use an LLM only to draft a plan from verified facts; validate its structured output before use. | `proposals.json` plus a patch for eligible cases: affected finding keys, exact versions/files, expected benefit, compatibility concerns, rollback, and evidence. No fabricated version or unbounded edit. |
| **Person 3 — investigation and approval gate** | Suspicious-change detection | Investigate at least one non-CVE risk (for example integrity, provenance, install script, or unexpected source change). Build the policy and human decision flow for proposed changes. A person, not the agent, grants final approval. | `investigations.json` and `approvals.json`: evidence, decision, reviewer, time, base commit, and exact patch hash. A changed patch or base commit invalidates approval. |
| **Person 4 — sandbox build and test** | Container and CI inspection, local image scan | Create an isolated candidate workspace at the baseline commit. Apply only the selected patch there, build the app/image, run available tests, capture logs, and classify failures against baseline behavior. | `validation.json` plus build/test logs: environment, commands, exit codes, timeouts, changed files, baseline comparison, and an explicit `passed`, `failed`, or `inconclusive` result. |
| **Person 5 — rescan and final report** | Evidence/risk, Streamlit app, Markdown/JSON reports | Rescan the candidate with the same available detectors; compare SBOMs, findings, and scan coverage. Present original risk, proposed action, approval, build/test outcome, remaining/new findings, and an audit trail. | `verification.json` and concise Day 2 report. Every claim links to baseline or candidate evidence; the full JSON remains available. |

Person 3 owns the **approval mechanism**; the actual reviewer is a human. Person
4 owns the sandbox, while Person 5 owns the independent after-scan. They should
agree on file formats before coding so the stages can run separately.

## Risk analysis: evidence first, AI second

Person 1 should separate **risk level** from **confidence in the assessment**.
Start with a transparent, configurable ranking rule using only fields we have:
severity, affected component, dependency path, whether a fix is known, and
documented exposure or reachability evidence. Unknown is a valid value. Do not
turn an absent dependency path into “unreachable,” or a high CVSS/severity into
“exploitable here.” Record which inputs raised or lowered the rank.

The LLM's role is to explain the supplied evidence and highlight missing context.
It must not invent CVEs, code paths, deployed exposure, or package versions. Store
its text as a draft, validate identifiers and cited evidence keys, and keep the
deterministic ranking available when the API is missing or fails. A model's
self-reported confidence is not a security control.

## Fix proposals and confidence gates

Person 2 should produce a **candidate**, not claim a verified fix. A Grype or
Trivy fixed version is a starting point. For a transitive package, inspect the
graph and manifest constraints to find the direct dependency that can actually
be changed. If the proposed version violates constraints or no patched version
exists, propose replacement, removal, mitigation, or manual review instead of
inventing an upgrade. Keep the patch small and list every changed file.
Do not ask an agent to fix every finding in one uncontrolled patch. Start with
one finding, or a bounded group that shares the same direct dependency; verify
it, then repeat. This makes failures and risk changes attributable to a change.

Use three separate fields:

1. **Risk confidence:** how well the threat to this application is supported.
2. **Proposal confidence:** how well a specific change is supported by advisories,
   dependency constraints, and the allowed edit scope.
3. **Validation result:** what the sandbox and after-scan actually demonstrated.

An initial configurable threshold (for example, proposal confidence >= 0.85)
may allow an **automatic attempt in the disposable sandbox** only when all
deterministic gates pass: a real fixed version, a known affected component, a
bounded patch, no secret or infrastructure change, and an available sandbox.
This number is a pilot setting, not a calibrated probability; measure false
positives and adjust it using test fixtures. A low-confidence or policy-sensitive
proposal is sent to a reviewer before any patch attempt. Neither threshold
authorizes merging, deployment, or changes to the original target. Final adoption
always requires human approval of the exact patch and validation evidence.

## Person 3: approval record and policy

The review screen or CLI record should show the finding and evidence, proposed
diff, dependency and version rationale, expected risk reduction, compatibility
concerns, rollback, sandbox logs, and before/after scan. Available decisions:
`approve`, `reject`, and `request_changes`. Store reviewer identity, timestamp,
reason, baseline commit, target repo, and patch hash. Reapproval is required if
any of those inputs change. Do not put API keys, source secrets, or raw credentials
in approval files or LLM prompts.

The policy gate can let a high-confidence candidate enter the sandbox without
interrupting a person. It cannot treat “the model said 95%” as approval. An
approved proposal is a handoff for a separate source-control action; Day 2 does
not auto-merge or deploy it.

## Person 4: isolated build and test

- Copy or create a fresh worktree at the **exact baseline commit**. Apply the
  proposed patch only to that disposable copy. Record the diff before running
  commands and reject unexpected file changes.
- Run builds and tests in a container or equivalent isolated environment with
  no host secrets, no privileged mode, no Docker socket inside the target, and
  bounded time, CPU, memory, disk, and network access. Allow network only where
  dependency installation truly needs it and record that access.
- Use reviewed command templates for the detected ecosystem. Do not execute an
  arbitrary shell command supplied by an LLM or by the target repository without
  a deliberate sandbox policy. Record tool versions, base image, exit codes, and
  logs. An unavailable tool is `not_run`, not `passed`.
- Run the baseline and candidate tests in comparable environments. NodeGoat's
  production image currently lacks `grunt-cli`, so its `npm test` fails there
  before any fix. That is a baseline limitation, not proof of a regression or of
  a successful remediation. Choose a demo target with runnable tests or create a
  controlled test environment for that target.
- Keep all changed artifacts in the run directory. Never overwrite the original
  checkout. A build/test failure, timeout, or missing test suite makes validation
  `failed` or `inconclusive`; it does not silently pass.

## Person 5: rescan and compare

Run the same available SBOM and vulnerability tools on baseline and candidate,
with versions and scan coverage recorded. Compare component versions, introduced
and removed dependencies, vulnerability observations, suspicious changes, and
container/CI findings. A finding's Day 1 ordinal ID (such as `VULN-001`) is not
stable between scans; introduce a stable comparison key from the advisory ID,
package URL/name, installed version, source, and affected artifact.

The final report must distinguish `resolved`, `remaining`, `new`, `unverified`,
and `not_scanned`. Passing tests alone does not prove a vulnerability is gone;
a clean rescan alone does not prove the application still works. If scanner
coverage differs, report that explicitly. Grype and Trivy may describe the same
issue, so group related observations while preserving both raw evidence records.
Show the approval decision and validation status next to the proposed action.

## Shared implementation contract

Before parallel coding, agree on one proposal and validation schema. Each stage
should consume a saved JSON artifact and write a new one under the run directory.
Minimum common fields: `repo_url`, `baseline_commit`, `finding_key`,
`source_finding_ids`, `evidence_refs`, `status`, `reason`, and artifact paths.
Proposals add `action`, `target_files`, `from_version`, `to_version`,
`patch_hash`, and `rollback`. Validation adds environment details, commands,
exit codes, test counts, and logs. Verification adds baseline/candidate scan
IDs and finding differences. A missing field or unsupported ecosystem should
produce an explicit blocked or inconclusive status, not a guessed result.

Suggested states: `detected -> assessed -> proposed -> sandbox_eligible ->
sandbox_running -> validated/inconclusive/failed -> rescanned -> awaiting_review
-> approved/rejected`. Save a timestamped event for each transition. Retries
must be safe and must not reuse approval for a different patch.

## Build order and handoffs

1. **All five:** agree on schemas, stable finding keys, status names, and one demo
   repository/commit with runnable baseline tests.
2. **People 1 and 3:** produce grounded risk and non-CVE investigation records.
   **Person 2:** produce one small, verifiable candidate using a real advisory.
3. **Person 4:** run the candidate in a disposable sandbox and return build/test
   evidence. No source branch or target checkout is modified.
4. **Person 5:** rescan the candidate and generate the before/after report.
5. **Person 3 and a human reviewer:** examine the exact patch and evidence,
   record approval or rejection, and invalidate it if the patch changes.
6. Integrate the stages through the orchestrator only after each artifact can be
   produced and read independently. Keep the Day 1 scan usable when a Day 2
   stage is unavailable.

## Day 2 demonstration and definition of done

Demonstrate one known vulnerability with a real candidate version and one
non-CVE suspicious change. Show the baseline scan, contextual ranking, exact
patch, sandbox build/test, after-scan, remaining or new risk, and a human
decision. Also demonstrate a blocked case: no safe version, failed tests,
missing scanner, or low-confidence proposal. It must remain visibly unapproved.

Day 2 is complete when reviewers can reproduce the evidence chain, see which
stages ran, understand why a fix was proposed, and tell whether it actually
reduced risk without breaking the tested application. If that cannot be shown,
the report says `inconclusive` and names the missing evidence.
