import json
from pathlib import Path

import networkx as nx


def load_sbom(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_graph(sbom: dict):
    """Build a directed dependency graph from a CycloneDX SBOM."""
    G = nx.DiGraph()

    root = sbom.get("metadata", {}).get("component", {})
    root_ref = root.get("bom-ref") or root.get("name", "root-app")
    G.add_node(
        root_ref,
        name=root.get("name", "root-app"),
        version=root.get("version", ""),
        kind="root",
    )

    for c in sbom.get("components", []):
        ref = c.get("bom-ref") or c.get("purl")
        if not ref:
            continue
        G.add_node(
            ref,
            name=c.get("name"),
            group=c.get("group"),
            version=c.get("version"),
            purl=c.get("purl"),
            scope=c.get("scope"),
            kind="component",
        )

    for dep in sbom.get("dependencies", []):
        parent = dep.get("ref")
        for child in dep.get("dependsOn", []):
            if parent in G and child in G:
                G.add_edge(parent, child)

    # Fallback: if the root has no edges, attach it to every node with no parent
    if G.out_degree(root_ref) == 0:
        for n in list(G.nodes):
            if n != root_ref and G.in_degree(n) == 0:
                G.add_edge(root_ref, n)

    return G, root_ref


def annotate(G: nx.DiGraph, root_ref: str) -> nx.DiGraph:
    """Mark each node as direct/transitive and record how it enters the app."""
    paths = nx.single_source_shortest_path(G, root_ref)
    direct = set(G.successors(root_ref))

    for n in G.nodes:
        if n == root_ref:
            continue
        p = paths.get(n)
        G.nodes[n]["direct"] = n in direct
        G.nodes[n]["depth"] = (len(p) - 1) if p else None
        G.nodes[n]["path"] = p
        # The direct dependency that pulled this component in
        G.nodes[n]["introduced_by"] = p[1] if p and len(p) > 1 else None
    return G


def export_json(G: nx.DiGraph, root_ref: str, out_path: str = "out/graph.json"):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "root": root_ref,
        "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
        "edges": [{"from": u, "to": v} for u, v in G.edges],
    }
    Path(out_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_path


def export_html(G: nx.DiGraph, root_ref: str, out_path: str = "out/graph.html"):
    from pyvis.network import Network

    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff")
    for n, d in G.nodes(data=True):
        label = f"{d.get('name')}@{d.get('version')}" if d.get("version") else str(d.get("name"))
        if n == root_ref:
            color, size = "#e6007e", 30
        elif d.get("direct"):
            color, size = "#1f77b4", 18
        else:
            color, size = "#9aa5b1", 10
        net.add_node(n, label=label, color=color, size=size, title=d.get("purl") or label)
    for u, v in G.edges:
        net.add_edge(u, v)
    net.write_html(out_path)
    return out_path


def summarize(G: nx.DiGraph, root_ref: str) -> dict:
    comps = [n for n in G.nodes if n != root_ref]
    direct = [n for n in comps if G.nodes[n].get("direct")]
    depths = [G.nodes[n]["depth"] for n in comps if G.nodes[n].get("depth") is not None]
    return {
        "total_components": len(comps),
        "direct": len(direct),
        "transitive": len(comps) - len(direct),
        "max_depth": max(depths) if depths else 0,
        "is_dag": nx.is_directed_acyclic_graph(G),
    }