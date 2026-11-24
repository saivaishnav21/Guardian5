"""Print the shape of the files in a run folder.

Usage: python scripts/peek_run.py runs/<timestamp>
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guardian.risk import extract_findings  # noqa: E402

run = Path(sys.argv[1])
FILES = ["vulnerability.json", "suspicious.json", "container_ci.json",
         "evidence_risk.json", "report.json", "state.json"]

for name in FILES:
    p = run / name
    if not p.exists():
        print(f"-- {name}: MISSING")
        continue
    data = json.loads(p.read_text(encoding="utf-8"))
    keys = list(data.keys())[:12] if isinstance(data, dict) else f"list of {len(data)}"
    findings = extract_findings(data)
    if not findings and isinstance(data, dict) and isinstance(data.get("state"), dict):
        findings = extract_findings(data["state"])
    print(f"-- {name}: {type(data).__name__}; keys={keys}; findings found={len(findings)}")
    if findings:
        print("   first finding:", json.dumps(findings[0], default=str)[:1200])

g = run / "graph.json"
if g.exists():
    graph = json.loads(g.read_text(encoding="utf-8"))
    print("-- graph.json scope values:", Counter(n.get("scope") for n in graph.get("nodes", [])))