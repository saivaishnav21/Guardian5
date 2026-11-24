from guardian.agents import recon, sbom_graph, suspicious, vulnerability, container_ci, evidence_risk
from guardian.agents.base import RunContext
from guardian.report import generate as generate_report

# Ordered Day 1 pipeline. Validation and automated remediation remain Day 2 work.
PIPELINE = [
    ("Recon Agent", recon.run),
    ("SBOM & Graph Agent", sbom_graph.run),
    ("Vulnerability Agent", vulnerability.run),
    ("Suspicious Investigation Agent", suspicious.run),
    ("Container & CI Agent", container_ci.run),
    ("Evidence & Risk Agent", evidence_risk.run),
]


def run_pipeline(repo_url: str) -> RunContext:
    ctx = RunContext.create(repo_url)
    print(f"Run directory: {ctx.run_dir}")
    for name, fn in PIPELINE:
        print(f"\n>> {name}")
        fn(ctx)
    md_path, json_path = generate_report(ctx)
    ctx.state["report"] = {"markdown": str(md_path), "json": str(json_path)}
    ctx.save("state.json", {"state": ctx.state, "log": ctx.log})
    print(f"\nDone. Graph: {ctx.state['graph']['graph_html']}")
    print(f"Report: {md_path}")
    return ctx
