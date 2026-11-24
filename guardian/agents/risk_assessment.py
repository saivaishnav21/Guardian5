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

    result = assess(findings, graph, meta={
        "run_dir": str(ctx.run_dir),
        "repo_url": ctx.repo_url,
        "baseline_commit": ctx.state.get("recon", {}).get("commit"),
        "findings_loaded_from": "ctx.state",
    })
    ai_by_id = {
        finding.get("id"): finding.get("ai_assessment")
        for finding in ctx.state.get("processed_findings", [])
        if isinstance(finding, dict)
        and (finding.get("ai_assessment") or {}).get("status") == "completed"
    }
    advisory_count = 0
    for item in result["items"]:
        advisory = next((ai_by_id[fid] for fid in item["finding_ids"] if fid in ai_by_id), None)
        if advisory:
            item["ai_advisory"] = advisory
            item["ai_disagrees_with_rank"] = advisory["priority"] != item["risk_level"]
            advisory_count += 1
    result["method"]["ai_advisory_count"] = advisory_count
    result["method"]["note"] += " Optional AI advice is shown separately and never changes the score."
    out = write_assessment(result, ctx.run_dir / "risk_assessment.json")

    ctx.state["risk_assessment"] = {
        "path": out,
        "fingerprint": result["ranking_fingerprint"],
        "summary": result["summary"],
    }
    ctx.note(AGENT, f"ranked {result['summary']['ranked_items']} items from "
                    f"{result['summary']['input_findings']} findings: {result['summary']['by_level']}")
