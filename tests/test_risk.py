from guardian.risk import assess


def _f(i, sev, comp="a@1.0.0", title="CVE-2024-0001 in a", ev=None,
       typ="vulnerability", fix=None, agent="Vulnerability Agent"):
    return {"id": i, "type": typ, "title": title, "component": comp,
            "dependency_path": [], "evidence": ev or {}, "severity": sev,
            "source_agent": agent, "fix": fix}


GRAPH = {
    "root": "r",
    "nodes": [
        {"id": "r", "name": "app", "version": "1.0.0", "kind": "root"},
        {"id": "n1", "name": "a", "version": "1.0.0", "scope": "required",
         "direct": True, "depth": 1, "path": ["r", "n1"], "introduced_by": "n1"},
    ],
    "edges": [],
}


def test_same_input_same_ranking_regardless_of_order():
    fs = [_f("VULN-1", "high"),
          _f("VULN-2", "critical", comp="b@2.0.0", title="CVE-2024-0002 in b")]
    r1 = assess(fs, GRAPH)
    r2 = assess(list(reversed(fs)), GRAPH)
    assert r1["ranking_fingerprint"] == r2["ranking_fingerprint"]
    assert [i["key"] for i in r1["items"]] == [i["key"] for i in r2["items"]]


def test_duplicates_from_two_scanners_become_one_item():
    fs = [_f("VULN-1", "high", ev={"scanner": "grype"}),
          _f("VULN-2", "high", ev={"scanner": "trivy"}, agent="Container Agent")]
    r = assess(fs, GRAPH)
    assert r["summary"]["ranked_items"] == 1
    assert r["items"][0]["scanners"] == ["grype", "trivy"]


def test_unknowns_are_listed_and_not_scored():
    r = assess([_f("VULN-1", "medium")], GRAPH)
    item = r["items"][0]
    assert any("reachability" in u for u in item["unknowns"])
    assert not any("reachab" in b["factor"] for b in item["score_breakdown"])