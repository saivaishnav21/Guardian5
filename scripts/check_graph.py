import json
import sys
from pathlib import Path

runs = sorted(p for p in Path("runs").glob("*") if p.is_dir())
run = Path(sys.argv[1]) if len(sys.argv) > 1 else runs[-1]

g = json.loads((run / "graph.json").read_text(encoding="utf-8"))
nodes, edges = g["nodes"], g["edges"]
comps = [n for n in nodes if n.get("kind") == "component"]
direct = [n for n in comps if n.get("direct")]
unreachable = [n for n in comps if n.get("depth") is None]

print("run:", run)
print("nodes:", len(nodes), "| edges:", len(edges))
print("components:", len(comps), "| direct:", len(direct), "| transitive:", len(comps) - len(direct))
print("unreachable from root:", len(unreachable))
print("node keys:", sorted(nodes[-1].keys()))

reachable = [n for n in comps if n.get("depth") is not None]
if reachable:
    deep = max(reachable, key=lambda n: n["depth"])
    print(f"deepest: {deep['name']}@{deep.get('version')} (depth {deep['depth']})")
    print("sample path:", " -> ".join(deep["path"]))

if len(comps) and len(direct) == len(comps):
    print("WARNING: every component is 'direct'. The SBOM probably had no usable "
          "dependency edges, so the fallback attached everything to the root.")
if not edges:
    print("WARNING: graph has no edges.")