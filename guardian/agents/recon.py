import re
import shutil
import subprocess

from guardian.agents.base import RunContext

AGENT = "Recon Agent"

# Only public GitHub repos are accepted (sandbox rule: no outside infrastructure)
URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")
SKIP_DIRS = {".git", "node_modules"}

ECOSYSTEM_FILES = {
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "pom.xml": "maven", "build.gradle": "gradle",
    "requirements.txt": "pypi", "poetry.lock": "pypi", "Pipfile.lock": "pypi",
    "go.mod": "go",
}
NPM_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def run(ctx: RunContext) -> None:
    url = ctx.repo_url
    if not URL_RE.match(url):
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are allowed.")

    dest = ctx.run_dir / "target"
    ctx.note(AGENT, f"cloning {url} (shallow)")
    subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], check=True)
    commit = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    found = {"manifests": [], "dockerfiles": [], "compose_files": [], "ci_workflows": []}
    ecosystems = set()

    for p in dest.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(dest)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        name = p.name
        if name in ECOSYSTEM_FILES:
            found["manifests"].append(str(rel))
            ecosystems.add(ECOSYSTEM_FILES[name])
        if name.lower().startswith("dockerfile") or name.lower().endswith(".dockerfile"):
            found["dockerfiles"].append(str(rel))
        if name in COMPOSE_NAMES:
            found["compose_files"].append(str(rel))
        if (len(rel.parts) >= 3 and rel.parts[0] == ".github" and rel.parts[1] == "workflows"
                and p.suffix in {".yml", ".yaml"}):
            found["ci_workflows"].append(str(rel))

    actions = []
    # npm project without a lockfile: resolve one WITHOUT installing or running scripts
    has_lock = any((dest / lf).exists() for lf in NPM_LOCKFILES)
    if (dest / "package.json").exists() and not has_lock:
        npm = shutil.which("npm")
        if not npm:
            raise RuntimeError("npm not found. Install Node.js 20 LTS first.")
        ctx.note(AGENT, "no lockfile found, generating one (lockfile-only, scripts disabled)")
        subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts"],
                       cwd=dest, check=True)
        actions.append("generated package-lock.json via npm --package-lock-only --ignore-scripts")

    recon = {
        "repo_url": url,
        "commit": commit,
        "target_dir": str(dest),
        "ecosystems": sorted(ecosystems),
        **found,
        "actions_taken": actions,
    }
    ctx.state["recon"] = recon
    ctx.save("recon.json", recon)
    ctx.note(AGENT, f"commit {commit[:8]}, ecosystems={sorted(ecosystems)}, "
                    f"dockerfiles={len(found['dockerfiles'])}, workflows={len(found['ci_workflows'])}")