from guardian.agents.base import RunContext
from guardian.graph import (
    annotate, build_graph, export_html, export_json, load_sbom, summarize,
)
from guardian.sbom import generate_sbom

AGENT = "SBOM & Graph Agent"


def run(ctx: RunContext) -> None:
    recon = ctx.state["recon"]
    if "npm" not in recon["ecosystems"]:
        raise NotImplementedError(f"Ecosystems {recon['ecosystems']} not supported yet (npm only).")

    sbom_path = str(ctx.run_dir / "sbom.cdx.json")
    ctx.note(AGENT, "generating CycloneDX SBOM with cdxgen")
    generate_sbom(recon["target_dir"], sbom_path)

    sbom = load_sbom(sbom_path)
    G, root = build_graph(sbom)
    annotate(G, root)

    graph_json = export_json(G, root, str(ctx.run_dir / "graph.json"))
    graph_html = export_html(G, root, str(ctx.run_dir / "graph.html"))
    summary = summarize(G, root)

    ctx.state["graph"] = {
        "root": root,
        "summary": summary,
        "sbom_path": sbom_path,
        "graph_json": graph_json,
        "graph_html": graph_html,
    }
    ctx.save("graph_summary.json", ctx.state["graph"])
    ctx.note(AGENT, f"graph built: {summary}")