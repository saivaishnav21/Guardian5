"""Apply every eligible upgrade proposal in one disposable candidate workspace.

The single-proposal runner in guardian.sandbox answers "is this one change safe?".
This runner answers "what does the whole remediation set do to the application?".

Proposals are deduplicated per package: several findings often propose different
target versions for the same package, so the highest validated version wins and
the lower ones are recorded as superseded. Versions still come from the scanner's
recorded fix field. No model text is executed.

Usage:
    python -m guardian.batch_fix runs/<id> --image node:16.20.2-bullseye-slim
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import uuid
from pathlib import Path

from guardian.approval_gate import load_proposals, load_policy
from guardian.sandbox import (
    NPM_NAME, PROJECT_ROOT, VERSION, _archive_checkout, _diff_allowed,
    _docker_image, _docker_step, _read, _source_tree, _test_log_caveat,
    _test_reliability_note,
)


def _version_key(value: str) -> tuple:
    """Order versions numerically where possible; fall back to text."""
    parts = []
    for chunk in str(value).replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def select_upgrades(proposals: list[dict], threshold: int) -> tuple[list[dict], list[dict]]:
    """Pick the highest eligible target version per (manifest, package)."""
    best: dict[tuple[str, str], dict] = {}
    superseded, rejected = [], []
    for proposal in proposals:
        if proposal.get("result") != "upgrade":
            continue
        score = proposal.get("confidence_score")
        component = str(proposal.get("component") or "")
        package, separator, current = component.rpartition("@")
        version = proposal.get("target_version")
        manifest = proposal.get("manifest_file")
        if not (separator and NPM_NAME.fullmatch(package) and VERSION.fullmatch(current)
                and isinstance(version, str) and VERSION.fullmatch(version)
                and isinstance(manifest, str) and Path(manifest).name == "package.json"
                and isinstance(score, (int, float)) and not isinstance(score, bool)
                and score >= threshold):
            rejected.append({"finding_id": proposal.get("finding_id"),
                             "component": component, "reason": "not an eligible bounded npm upgrade"})
            continue
        key = (manifest, package)
        entry = {"finding_id": proposal.get("finding_id"), "package": package,
                 "manifest_file": manifest, "current_version": current,
                 "target_version": version, "risk_level": proposal.get("risk_level"),
                 "confidence_score": score}
        current_best = best.get(key)
        if current_best is None:
            best[key] = entry
        elif _version_key(version) > _version_key(current_best["target_version"]):
            superseded.append({**current_best, "superseded_by": version})
            best[key] = entry
        else:
            superseded.append({**entry, "superseded_by": current_best["target_version"]})
    return sorted(best.values(), key=lambda item: item["package"]), superseded + rejected


def run_batch(run_dir: str | Path, image: str, timeout_scale: int = 2) -> dict:
    """Build and test one candidate carrying every selected upgrade."""
    run = Path(run_dir).resolve()
    if not run.is_dir() or not run.is_relative_to((PROJECT_ROOT / "runs").resolve()):
        raise ValueError("run directory must be inside project runs")

    proposals = load_proposals(run / "proposals.json")
    threshold = load_policy().get("auto_sandbox_trial_threshold", 70)
    selected, skipped = select_upgrades(proposals, threshold)
    if not selected:
        raise ValueError("no eligible upgrade proposals in this run")

    manifests = {item["manifest_file"] for item in selected}
    if len(manifests) != 1:
        raise ValueError("batch mode supports one manifest; found: " + ", ".join(sorted(manifests)))
    relative = Path(next(iter(manifests)))

    state = _read(run / "state.json")["state"]
    commit = (state.get("recon") or {}).get("commit")
    trial_dir = run / "sandbox" / f"BATCH-{uuid.uuid4().hex[:8]}"
    trial_dir.mkdir(parents=True)

    validation = {
        "schema_version": 1, "mode": "batch", "status": "blocked",
        "baseline_commit": commit, "manifest_file": relative.as_posix(),
        "selected": selected, "skipped": skipped,
        "selected_count": len(selected), "skipped_count": len(skipped),
        "steps": {}, "patch_sha256": None, "changed_files": [], "image_id": None,
    }

    def save() -> dict:
        (trial_dir / "validation.json").write_text(
            json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        validation["artifact"] = str(trial_dir / "validation.json")
        return validation

    try:
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
        for item in selected:
            if not any(item["package"] in (data.get(section) or {})
                       for section in ("dependencies", "devDependencies")
                       if isinstance(data.get(section), dict)):
                raise ValueError(f"{item['package']} is not a direct dependency in the manifest")

        image_id = _docker_image(image)
        validation["image_id"] = image_id
        workdir = "/workspace" + ("/" + relative.parent.as_posix()
                                  if relative.parent != Path(".") else "")

        def step(name, folder, args, network, timeout):
            result = _docker_step(name, image_id, folder, workdir, args,
                                  network=network, timeout=timeout, output_dir=trial_dir)
            validation["steps"][name] = result
            return result

        specs = [f"{item['package']}@{item['target_version']}" for item in selected]
        print(f"[batch] applying {len(specs)} upgrade(s): {', '.join(specs)}", flush=True)
        patch = step("candidate_patch", candidate,
                     ["install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                      "--no-fund", "--save-exact", *specs], True, 180 * timeout_scale)
        if patch["status"] != "passed":
            validation.update(status="inconclusive",
                              reason="the combined upgrade set could not be resolved by npm")
            return save()

        if (_read(baseline / relative.with_name("package-lock.json")).get("lockfileVersion")
                != _read(lockfile).get("lockfileVersion")):
            raise ValueError("candidate changed the npm lockfile format; use a matching npm runtime")

        changed, diff = _diff_allowed(baseline, candidate, {
            relative.as_posix(), relative.with_name("package-lock.json").as_posix()})
        updated = _read(manifest)
        for item in selected:
            if not any((updated.get(section) or {}).get(item["package"]) == item["target_version"]
                       for section in ("dependencies", "devDependencies")
                       if isinstance(updated.get(section), dict)):
                raise ValueError(f"candidate manifest does not pin {item['package']}"
                                 f"@{item['target_version']}")
        (trial_dir / "patch.diff").write_bytes(diff)
        validation["patch_sha256"] = hashlib.sha256(diff).hexdigest()
        validation["changed_files"] = changed

        scripts = data.get("scripts") or {}
        note = _test_reliability_note(baseline)
        if note:
            validation["test_reliability_note"] = note

        for label, folder in (("baseline", baseline), ("candidate", candidate)):
            install = step(f"{label}_install", folder,
                           ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
                           True, 300 * timeout_scale)
            if install["status"] != "passed":
                validation.update(status="inconclusive" if label == "baseline" else "failed",
                                  reason=f"{label} dependency install did not pass")
                return save()
            if scripts.get("build"):
                build = step(f"{label}_build", folder, ["run", "build"], False, 180 * timeout_scale)
                if build["status"] != "passed":
                    validation.update(status="inconclusive" if label == "baseline" else "failed",
                                      reason=f"{label} build did not pass")
                    return save()
            else:
                validation["steps"][f"{label}_build"] = {"status": "skipped",
                                                         "reason": "no build script"}
            if scripts.get("test"):
                tests = step(f"{label}_test", folder, ["test"], False, 180 * timeout_scale)
                if tests["status"] != "passed":
                    validation.update(status="inconclusive" if label == "baseline" else "failed",
                                      reason=f"{label} application tests did not pass")
                    return save()
                caveat = _test_log_caveat(tests["log"])
                if caveat:
                    validation["steps"][f"{label}_test"]["caveat"] = caveat
            else:
                validation["steps"][f"{label}_test"] = {"status": "skipped",
                                                        "reason": "no test script"}

        empty = any(isinstance(s, dict) and (s.get("caveat") or s.get("status") == "skipped")
                    for name, s in validation["steps"].items() if name.endswith("_test"))
        if note or empty:
            validation.update(status="inconclusive", reason=(
                note or "the target has no runnable application test suite; "
                        "install and build succeeded but behaviour is unverified"))
        else:
            validation.update(status="passed",
                              reason="baseline and candidate install/build/test gates passed; rescan pending")
    except Exception as exc:  # noqa: BLE001 - recorded, never silently swallowed
        validation.update(status="inconclusive" if validation["image_id"] else "blocked",
                          reason=f"{type(exc).__name__}: {exc}")
    return save()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply every eligible upgrade proposal in one disposable candidate")
    parser.add_argument("run_dir")
    parser.add_argument("--image", required=True, help="locally available Node runtime image")
    args = parser.parse_args()
    result = run_batch(args.run_dir, args.image)
    print(json.dumps({key: result.get(key) for key in (
        "status", "reason", "selected_count", "skipped_count",
        "patch_sha256", "changed_files", "artifact")}, indent=2))
    print("\nSelected upgrades:")
    for item in result.get("selected", []):
        print(f"  {item['package']:20} {item['current_version']:10} -> {item['target_version']}")


if __name__ == "__main__":
    main()
