import argparse
import json
import subprocess
from pathlib import Path


BRANCH = "guardian-demo-tampered"
DEMO_PACKAGE = "lod-ash"


def run(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def read_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a safe static suspicious-change demo branch"
    )
    parser.add_argument("target_dir", type=Path)
    parser.add_argument("--base", default="")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()

    repo = args.target_dir.resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"{repo} is not a git repository")

    package_path = repo / "package.json"
    lockfile_path = repo / "package-lock.json"
    if not package_path.is_file() or not lockfile_path.is_file():
        raise SystemExit("package.json and package-lock.json are required")

    base = args.base.strip()
    if not base:
        for candidate in ("main", "master"):
            result = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", candidate],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                base = candidate
                break
    if not base:
        raise SystemExit("Could not determine a base branch")

    run(repo, "checkout", base)
    run(repo, "switch", "-C", BRANCH)

    package = read_object(package_path)
    dependencies = package.setdefault("dependencies", {})
    dependencies[DEMO_PACKAGE] = "1.0.0-demo"
    scripts = package.setdefault("scripts", {})
    scripts["postinstall"] = "echo guardian-demo-static-only"
    package_path.write_text(
        json.dumps(package, indent=2) + "\n",
        encoding="utf-8",
    )

    lockfile = read_object(lockfile_path)
    packages = lockfile.get("packages")
    if isinstance(packages, dict):
        packages[f"node_modules/{DEMO_PACKAGE}"] = {
            "name": DEMO_PACKAGE,
            "version": "1.0.0-demo",
            "resolved": "https://example.invalid/demo-package.tgz",
            "integrity": "sha512-GUARDIAN-DEMO-MODIFIED-INTEGRITY",
            "hasInstallScript": True,
        }
        existing = [
            details for details in packages.values()
            if isinstance(details, dict) and details.get("integrity")
        ]
        if existing:
            existing[0]["integrity"] = (
                "sha512-GUARDIAN-DEMO-MODIFIED-INTEGRITY"
            )
    else:
        dependencies = lockfile.setdefault("dependencies", {})
        dependencies[DEMO_PACKAGE] = {
            "version": "1.0.0-demo",
            "resolved": "https://example.invalid/demo-package.tgz",
            "integrity": "sha512-GUARDIAN-DEMO-MODIFIED-INTEGRITY",
            "hasInstallScript": True,
        }
    lockfile_path.write_text(
        json.dumps(lockfile, indent=2) + "\n",
        encoding="utf-8",
    )

    run(repo, "add", "package.json", "package-lock.json")
    commit = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "Add safe suspicious-change demo"],
        capture_output=True,
        text=True,
        check=False,
    )
    if commit.returncode != 0 and "nothing to commit" not in commit.stdout.lower():
        raise RuntimeError(commit.stderr.strip() or commit.stdout.strip())

    if args.push:
        remotes = run(repo, "remote")
        if not remotes:
            raise SystemExit("No git remote configured")
        run(repo, "push", "-u", "origin", BRANCH)

    print(f"Created branch: {BRANCH}")
    print("Static demo only; no package installation or script execution.")


if __name__ == "__main__":
    main()
