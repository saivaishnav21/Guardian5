from guardian.agents import recon, sbom_graph, suspicious
from guardian.agents.base import RunContext

# Ordered agent pipeline. Later phases add: vulnerability, suspicious-change, evidence/risk agents.
PIPELINE = [
    ("Recon Agent", recon.run),
    ("SBOM & Graph Agent", sbom_graph.run),
    ("Suspicious Change Agent", suspicious.run),
]


def run_pipeline(repo_url: str) -> RunContext:
    ctx = RunContext.create(repo_url)
    print(f"Run directory: {ctx.run_dir}")
    for name, fn in PIPELINE:
        print(f"\n>> {name}")
        fn(ctx)
    ctx.save("state.json", {"state": ctx.state, "log": ctx.log})
    print(f"\nDone. Open {ctx.state['graph']['graph_html']}")
    return ctx