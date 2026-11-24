"""One-proposal, disposable npm build/test trial. No fix is adopted here."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

from guardian.approval_gate import (
    load_proposals, may_auto_trial, may_trial, proposal_sha256,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NPM_NAME = re.compile(r"^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$", re.I)
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")
COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_PATCH_BYTES = 200 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _latest_review(run_dir: Path, proposal: dict) -> dict | None:
    path = run_dir / "approvals.json"
    if not path.is_file():
        return None
    history = _read(path)
    if not isinstance(history, list):
        raise ValueError("approvals.json must be a list")
    digest = proposal_sha256(proposal)
    return next((r for r in reversed(history) if isinstance(r, dict)
                 and r.get("proposal_sha256") == digest), None)


def _source_tree(run_dir: Path, state: dict, commit: str) -> Path:
    value = (state.get("recon") or {}).get("target_dir")
    if (not isinstance(value, str) or not value
            or not isinstance(commit, str) or not COMMIT.fullmatch(commit)):
        raise ValueError("recorded target checkout or baseline commit is invalid")
    target = Path(value)
    if not target.is_absolute():
        target = PROJECT_ROOT / target
    target = target.resolve()
    if not target.is_dir() or not (target / ".git").exists():
        raise ValueError("recorded target checkout is unavailable")
    if not target.is_relative_to((PROJECT_ROOT / "runs").resolve()):
        raise ValueError("target checkout must be inside project runs")
    found = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    if found.lower() != commit.lower():
        raise ValueError("target checkout no longer matches the recorded baseline commit")
    return target


def _archive_checkout(source: Path, commit: str, destination: Path, archive: Path) -> None:
    with archive.open("wb") as handle:
        result = subprocess.run(["git", "-C", str(source), "archive", "--format=tar", commit],
                                stdout=handle, stderr=subprocess.PIPE, timeout=90)
    if result.returncode:
        raise RuntimeError("git archive failed: " + result.stderr.decode(errors="replace")[:300])
    if archive.stat().st_size > MAX_SOURCE_ARCHIVE_BYTES:
        raise ValueError("repository archive exceeds the trial size limit")
    destination.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        extracted_bytes = 0
        for member in bundle:
            path = (destination / member.name).resolve()
            if not path.is_relative_to(destination.resolve()):
                raise ValueError("repository archive contains an unsafe path")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                extracted_bytes += member.size
                if extracted_bytes > MAX_EXTRACTED_BYTES:
                    raise ValueError("repository contents exceed the trial size limit")
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError("repository archive contains an unreadable file")
                with stream, path.open("wb") as output:
                    shutil.copyfileobj(stream, output)
                os.chmod(path, member.mode & 0o777)
            else:
                raise ValueError("repository archive contains a link or special file")


def _workspace_paths(root: Path) -> dict[str, str]:
    paths = {}
    for path in root.rglob("*"):
        if path.is_file():
            paths[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return paths


def _diff_allowed(baseline: Path, candidate: Path, allowed: set[str]) -> tuple[list[str], bytes]:
    before = _workspace_paths(baseline)
    after = _workspace_paths(candidate)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    if not changed or any(name not in allowed for name in changed):
        raise ValueError("candidate changed no files or changed files outside its manifest and lockfile")
    chunks = []
    for name in changed:
        old = (baseline / name).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if name in before else []
        new = (candidate / name).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if name in after else []
        chunks.extend(difflib.unified_diff(old, new, fromfile=f"baseline/{name}", tofile=f"candidate/{name}"))
    patch = "".join(chunks).encode("utf-8")
    if len(patch) > MAX_PATCH_BYTES:
        raise ValueError("candidate diff exceeds the trial size limit")
    return changed, patch


def _test_reliability_note(root: Path) -> str | None:
    """A forced Grunt success cannot establish that application tests passed."""
    gruntfile = root / "Gruntfile.js"
    if gruntfile.is_file() and re.search(
        r"grunt\.option\(\s*['\"]force['\"]\s*,\s*true\s*\)",
        gruntfile.read_text(encoding="utf-8", errors="replace"),
    ):
        return "Gruntfile enables force mode, so npm test may return success despite failed tasks"
    return None


def _test_log_caveat(log_path: str) -> str | None:
    output = Path(log_path).read_text(encoding="utf-8", errors="replace")
    if re.search(r"No files to check|No tests found|\b0 passing\b", output, re.I):
        return "test command exited without running application tests"
    return None


def _docker_image(image: str) -> str:
    result = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                            capture_output=True, text=True, timeout=30)
    if result.returncode or not result.stdout.strip().startswith("sha256:"):
        raise RuntimeError("the requested Docker image is not available locally")
    return result.stdout.strip()


def _docker_step(name: str, image_id: str, folder: Path, workdir: str,
                 args: list[str], *, network: bool, timeout: int, output_dir: Path) -> dict:
    print(f"[sandbox] {name}: npm {' '.join(args)}", flush=True)
    container = f"guardian-trial-{uuid.uuid4().hex[:12]}"
    log_path = output_dir / f"{name}.log"
    command = [
        "docker", "run", "--rm", "--name", container, "--pull=never",
        "--network", "bridge" if network else "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "2g", "--memory-swap", "2g",
        "--cpus", "2", "--user", "1000:1000", "--tmpfs", "/tmp:rw,nosuid,size=512m",
        "--env", "HOME=/tmp", "--env", "NPM_CONFIG_CACHE=/tmp/npm-cache",
        "--mount", f"type=bind,source={folder.resolve()},target=/workspace",
        "--workdir", workdir, "--entrypoint", "npm", image_id, *args,
    ]
    started = time.monotonic()
    timed_out = False
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
            subprocess.run(["docker", "rm", "-f", container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            code = None
    status = "timeout" if timed_out else "passed" if code == 0 else "failed"
    print(f"[sandbox] {name}: {status} (exit={code})", flush=True)
    return {"status": status,
            "exit_code": code, "seconds": round(time.monotonic() - started, 2),
            "network": "bridge" if network else "none", "command": ["npm", *args],
            "log": str(log_path)}


def run_trial(run_dir: str | Path, finding_id: str, image: str) -> dict:
    """Validate one candidate; all generated files remain inside the selected run."""
    run = Path(run_dir).resolve()
    if not run.is_dir() or not run.is_relative_to((PROJECT_ROOT / "runs").resolve()):
        raise ValueError("run directory must be inside project runs")
    proposals_path = run / "proposals.json"
    proposals = [p for p in load_proposals(proposals_path) if p.get("finding_id") == finding_id]
    if len(proposals) != 1:
        raise ValueError("finding ID must identify exactly one proposal")
    proposal = proposals[0]
    report = _read(run / "report.json")
    state = _read(run / "state.json")["state"]
    digest = proposal_sha256(proposal)
    trial_dir = run / "sandbox" / f"{finding_id}-{uuid.uuid4().hex[:8]}"
    trial_dir.mkdir(parents=True)
    validation = {"schema_version": 1, "finding_id": finding_id,
                  "proposal_sha256": digest, "baseline_commit": proposal.get("baseline_commit"),
                  "status": "blocked", "approval_mode": None, "steps": {},
                  "patch_sha256": None, "changed_files": [], "image_id": None}

    def save() -> dict:
        (trial_dir / "validation.json").write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        validation["artifact"] = str(trial_dir / "validation.json")
        return validation

    try:
        auto_blocks = may_auto_trial(proposal, report, proposals_path)
        if not auto_blocks:
            validation["approval_mode"] = "automatic_sandbox_trial"
        else:
            review = _latest_review(run, proposal)
            manual_blocks = may_trial(review, proposal, report, proposals_path) if review else ["human preflight approval is missing"]
            if manual_blocks:
                validation["reason"] = "; ".join(auto_blocks + manual_blocks)
                return save()
            validation["approval_mode"] = "human_preflight"

        component = str(proposal.get("component") or "")
        package, separator, current = component.rpartition("@")
        version = proposal.get("target_version")
        manifest_name = proposal.get("manifest_file")
        expected = f"npm install --package-lock-only --ignore-scripts {package}@{version}"
        if (proposal.get("result") != "upgrade" or not separator or not NPM_NAME.fullmatch(package)
                or not VERSION.fullmatch(current) or not isinstance(version, str)
                or not VERSION.fullmatch(version) or not isinstance(manifest_name, str)
                or proposal.get("command") != expected):
            raise ValueError("proposal does not contain a supported bounded npm upgrade")
        relative = Path(manifest_name)
        if relative.is_absolute() or ".." in relative.parts or relative.name != "package.json":
            raise ValueError("proposal manifest path is unsafe")
        commit = proposal.get("baseline_commit")
        target = _source_tree(run, state, commit)
        baseline = trial_dir / "baseline"
        candidate = trial_dir / "candidate"
        _archive_checkout(target, commit, baseline, trial_dir / "source.tar")
        shutil.copytree(baseline, candidate)
        manifest = candidate / relative
        lockfile = manifest.with_name("package-lock.json")
        if not manifest.is_file() or not lockfile.is_file():
            raise ValueError("supported npm manifest and lockfile are required")
        data = _read(manifest)
        if not isinstance(data, dict):
            raise ValueError("npm manifest must be a JSON object")
        if not any(package in (data.get(section) or {}) for section in ("dependencies", "devDependencies")
                   if isinstance(data.get(section), dict)):
            raise ValueError("proposed package is not a direct dependency in the manifest")
        image_id = _docker_image(image)
        validation["image_id"] = image_id
        workdir = "/workspace" + ("/" + relative.parent.as_posix() if relative.parent != Path(".") else "")

        def step(name: str, folder: Path, args: list[str], network: bool, timeout: int) -> dict:
            result = _docker_step(name, image_id, folder, workdir, args,
                                  network=network, timeout=timeout, output_dir=trial_dir)
            validation["steps"][name] = result
            return result

        patch = step("candidate_patch", candidate,
                     ["install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                      "--no-fund", "--save-exact", f"{package}@{version}"], True, 180)
        if patch["status"] != "passed":
            validation.update(status="inconclusive", reason="candidate patch could not be prepared")
            return save()
        if _read(baseline / relative.with_name("package-lock.json")).get("lockfileVersion") != _read(lockfile).get("lockfileVersion"):
            raise ValueError("candidate changed the npm lockfile format; use a matching npm runtime")
        changed, diff = _diff_allowed(baseline, candidate, {
            relative.as_posix(), relative.with_name("package-lock.json").as_posix()})
        updated = _read(manifest)
        if not any((updated.get(section) or {}).get(package) == version
                   for section in ("dependencies", "devDependencies")
                   if isinstance(updated.get(section), dict)):
            raise ValueError("candidate manifest does not pin the proposed version")
        (trial_dir / "patch.diff").write_bytes(diff)
        validation["patch_sha256"] = hashlib.sha256(diff).hexdigest()
        validation["changed_files"] = changed

        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict) or not scripts.get("test"):
            validation.update(status="inconclusive", reason="baseline has no application test script")
            return save()
        reliability_note = _test_reliability_note(baseline)
        if reliability_note:
            validation["test_reliability_note"] = reliability_note
        for label, folder in (("baseline", baseline), ("candidate", candidate)):
            install = step(f"{label}_install", folder,
                           ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], True, 300)
            if install["status"] != "passed":
                validation.update(status="inconclusive" if label == "baseline" else "failed",
                                  reason=f"{label} dependency install did not pass")
                return save()
            if scripts.get("build"):
                build = step(f"{label}_build", folder, ["run", "build"], False, 180)
                if build["status"] != "passed":
                    validation.update(status="inconclusive" if label == "baseline" else "failed",
                                      reason=f"{label} build did not pass")
                    return save()
            else:
                validation["steps"][f"{label}_build"] = {"status": "skipped", "reason": "no build script"}
            tests = step(f"{label}_test", folder, ["test"], False, 180)
            if tests["status"] != "passed":
                validation.update(status="inconclusive" if label == "baseline" else "failed",
                                  reason=f"{label} application tests did not pass")
                return save()
            no_tests = _test_log_caveat(tests["log"])
            if no_tests:
                validation.update(status="inconclusive", reason=f"{label}: {no_tests}")
                return save()
        if reliability_note:
            validation.update(status="inconclusive", reason=reliability_note)
        else:
            validation.update(status="passed", reason="baseline and candidate build/test gates passed; rescan pending")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        validation.update(status="inconclusive" if validation["approval_mode"] else "blocked",
                          reason=f"{type(exc).__name__}: {exc}")
    return save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate one Guardian proposal in disposable Docker workspaces")
    parser.add_argument("run_dir", help="completed scan run directory")
    parser.add_argument("finding_id", help="one upgrade proposal finding ID")
    parser.add_argument("--image", required=True, help="locally available Node runtime image")
    args = parser.parse_args()
    result = run_trial(args.run_dir, args.finding_id, args.image)
    print(json.dumps({key: result.get(key) for key in
                      ("status", "reason", "approval_mode", "patch_sha256", "artifact")}, indent=2))


if __name__ == "__main__":
    main()
