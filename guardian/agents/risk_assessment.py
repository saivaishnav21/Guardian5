from guardian.agents.base import RunContext
from guardian.risk import assess, load_json, write_assessment

AGENT = "Risk Assessment Agent"


def run(ctx: RunContext) -> None:
    findings = ctx.state.get("findings", [])
    graph = {}
    graph_path = (ctx.state.get("graph") or {}).get("graph_json")
    if graph_path:
        graph = load_json(graph_path)
    else:
        ctx.note(AGENT, "graph.json not found in state; ownership and scope will be unknown")

    result = assess(findings, graph, meta={"run_dir": str(ctx.run_dir), "findings_loaded_from": "ctx.state"})
    out = write_assessment(result, ctx.run_dir / "risk_assessment.json")

    ctx.state["risk_assessment"] = {
        "path": out,
        "fingerprint": result["ranking_fingerprint"],
        "summary": result["summary"],
    }
    ctx.note(AGENT, f"ranked {result['summary']['ranked_items']} items from "
                    f"{result['summary']['input_findings']} findings: {result['summary']['by_level']}")