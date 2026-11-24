"""Start a candidate application with its own Compose stack and check it serves traffic.

This answers the question a unit-test suite cannot when the target has no tests:
does the application still boot and respond after the dependency upgrades?

Unlike guardian.sandbox, this needs a network and starts real services, so it is
run deliberately and never as part of an automatic trial. It tears the stack
down afterwards, including volumes.

Usage:
    python scripts/smoke_test_app.py runs/<id>/sandbox/BATCH-xxxx/candidate --label candidate
    python scripts/smoke_test_app.py runs/<id>/sandbox/BATCH-xxxx/baseline  --label baseline
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")


def _compose(app_dir: Path, project: str, *args: str, timeout: int = 600):
    return subprocess.run(
        ["docker", "compose", "-p", project, *args],
        cwd=str(app_dir), capture_output=True, text=True, timeout=timeout,
    )


def _probe(url: str, deadline: float) -> dict:
    """Poll until the app answers with any HTTP status, or time runs out."""
    last = "no attempt made"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return {"reachable": True, "http_status": response.status,
                        "bytes": len(response.read(4096))}
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx still proves the server is up and routing.
            return {"reachable": True, "http_status": exc.code, "bytes": 0}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(3)
    return {"reachable": False, "http_status": None, "last_error": last}


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot a candidate app and check it responds")
    parser.add_argument("app_dir", help="directory containing the application and its compose file")
    parser.add_argument("--label", default="candidate", help="baseline or candidate")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--path", default="/", help="HTTP path to probe")
    parser.add_argument("--timeout", type=int, default=240, help="seconds to wait for a response")
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    if not app_dir.is_dir():
        raise SystemExit(f"{app_dir} is not a directory")
    if not LABEL_RE.match(args.label):
        raise SystemExit("--label must be lowercase letters, digits, dash or underscore")
    compose_file = next((app_dir / name for name in COMPOSE_NAMES if (app_dir / name).is_file()), None)
    if compose_file is None:
        raise SystemExit(f"No compose file in {app_dir}; cannot start the application.")

    project = f"guardian-smoke-{args.label}"
    url = f"http://localhost:{args.port}{args.path}"
    record = {"schema_version": 1, "label": args.label, "app_dir": str(app_dir),
              "compose_file": compose_file.name, "url": url, "status": "error"}

    print(f"[smoke] starting {args.label} stack from {compose_file.name} (this builds images)")
    started = time.monotonic()
    try:
        # Clear any stack or network left behind by an interrupted earlier run.
        _compose(app_dir, project, "down", "-v", "--remove-orphans", timeout=180)
        subprocess.run(["docker", "network", "rm", f"{project}_default"],
                       capture_output=True, text=True, timeout=60)
        up = _compose(app_dir, project, "up", "-d", "--build")
        record["compose_up_exit"] = up.returncode
        if up.returncode != 0:
            record.update(status="failed", reason="compose up failed",
                          detail=(up.stderr or up.stdout)[-2000:])
            print("[smoke] compose up FAILED")
        else:
            print(f"[smoke] stack up; probing {url} for up to {args.timeout}s")
            probe = _probe(url, time.monotonic() + args.timeout)
            record["probe"] = probe
            if probe["reachable"]:
                record.update(status="passed",
                              reason=f"application answered HTTP {probe['http_status']}")
                print(f"[smoke] PASSED — HTTP {probe['http_status']}")
            else:
                record.update(status="failed",
                              reason="application did not answer before the timeout")
                print("[smoke] FAILED — no response")
            logs = _compose(app_dir, project, "logs", "--no-color", "--tail", "200", timeout=120)
            record["logs_tail"] = (logs.stdout or logs.stderr)[-6000:]
    finally:
        print("[smoke] tearing down")
        down = _compose(app_dir, project, "down", "-v", "--remove-orphans", timeout=300)
        record["torn_down"] = down.returncode == 0

    record["seconds"] = round(time.monotonic() - started, 1)
    out = app_dir.parent / f"app_smoke_{args.label}.json"
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"[smoke] {record['status']}: {record.get('reason', '')}")
    print(f"[smoke] record: {out}")
    print("[smoke] A passing smoke test shows the app boots and serves a request. "
          "It is not a functional test suite.")


if __name__ == "__main__":
    main()
