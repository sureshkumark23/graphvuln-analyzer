from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.parser.dependency_parser import DependencyParser
from backend.graph.resolver import TransitiveDependencyResolver
from backend.graph.graph_builder import GraphBuilder
from backend.cve.cve_enricher import CVEEnricher
from backend.propagation.propagation_simulator import PropagationSimulator

import urllib3
urllib3.disable_warnings()

app = FastAPI(
    title      = "GraphVuln Analyzer API",
    description= "Graph-Based Vulnerability Propagation Analyzer",
    version    = "1.0.0"
)

# Allow React frontend to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["http://localhost:3000"],
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ── HEALTH CHECK ──────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status" : "running",
        "tool"   : "GraphVuln Analyzer",
        "version": "1.0.0"
    }


# ── MAIN ANALYZE ENDPOINT ─────────────────────────────────
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """
    Main endpoint.
    Upload package.json or requirements.txt
    Returns full analysis: graph + CVEs + propagation + ranking
    """

    # Validate file type
    allowed = ["package.json", "requirements.txt"]
    if not any(file.filename.endswith(a) for a in allowed):
        raise HTTPException(
            status_code = 400,
            detail      = "Only package.json or requirements.txt allowed"
        )

    # Save uploaded file to temp location
    suffix   = ".json" if "package.json" in file.filename else ".txt"
    filename = "package.json" if "package.json" in file.filename else "requirements.txt"

    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, 
        prefix=filename.replace(".", "_") + "_"
    ) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    # Rename so parser recognises it
    proper_path = tmp_path.replace(
        os.path.basename(tmp_path),
        filename
    )
    os.rename(tmp_path, proper_path)

    try:
        # Step 1 — Parse
        parser     = DependencyParser()
        parsed     = parser.parse(proper_path)
        ecosystem  = parsed["ecosystem"]
        packages   = parsed["packages"]

        if not packages:
            raise HTTPException(
                status_code=400,
                detail="No packages found in file"
            )

        # Step 2 — Resolve transitive dependencies
        resolver   = TransitiveDependencyResolver(max_depth=3)
        resolved   = resolver.resolve(packages, ecosystem)

        # Step 3 — Build graph
        builder    = GraphBuilder()
        G          = builder.build(resolved)
        stats      = builder.get_stats()

        # Step 4 — Enrich with CVEs
        enricher   = CVEEnricher()
        G          = enricher.enrich(G, ecosystem)

        # Step 5 — Simulate propagation
        simulator  = PropagationSimulator()
        sim_output = simulator.simulate(G)

        # Step 6 — Build response
        # Convert graph to JSON-serializable format
        nodes = []
        for node_id, data in G.nodes(data=True):
            nodes.append({
                "id"             : node_id,
                "name"           : data["name"],
                "version"        : data["version"],
                "depth"          : data["depth"],
                "has_cve"        : data["has_cve"],
                "cvss_max"       : data["cvss_max"],
                "risk_score"     : data["risk_score"],
                "dependent_count": data["dependent_count"],
                "pagerank"       : data["pagerank"],
                "cve_count"      : len(data.get("cve_list", [])),
                "cve_list"       : data.get("cve_list", [])
            })

        edges = []
        for src, dst in G.edges():
            edges.append({"source": src, "target": dst})

        return {
            "status"   : "success",
            "ecosystem": ecosystem,
            "summary"  : {
                "total_packages"  : stats["total_nodes"],
                "total_edges"     : stats["total_edges"],
                "vulnerable_count": sim_output.get("total_cve_nodes", 0),
                "affected_count"  : sim_output.get("total_affected_nodes", 0),
                "clean_count"     : stats["total_nodes"] - sim_output.get("total_cve_nodes", 0),
            },
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "risk_ranking" : sim_output.get("risk_ranking", []),
            "propagation"  : {
                k: {
                    "cve_node"      : v["cve_node"],
                    "cvss_score"    : v["cvss_score"],
                    "blast_radius"  : v["blast_radius"],
                    "affected_nodes": v["affected_nodes"]
                }
                for k, v in sim_output.get("propagation", {}).items()
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # Clean up temp file
        if os.path.exists(proper_path):
            os.remove(proper_path)


# ── GRAPH ENDPOINT ────────────────────────────────────────
@app.get("/graph/{ecosystem}")
def get_sample_graph(ecosystem: str):
    """Returns a quick sample graph for testing frontend."""
    return {
        "message"   : f"Sample graph for {ecosystem}",
        "ecosystem" : ecosystem
    }