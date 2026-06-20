import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.graph.resolver import TransitiveDependencyResolver
from backend.graph.graph_builder import GraphBuilder
from backend.cve.cve_enricher import CVEEnricher

print("=" * 55)
print("TEST — CVE Enricher")
print("=" * 55)

# Use older lodash version — known to have CVEs
packages = [
    {"name": "lodash",  "version": "4.17.20"},
    {"name": "express", "version": "4.18.2"}
]

# Step 1 — Resolve
resolver = TransitiveDependencyResolver(max_depth=1)
result   = resolver.resolve(packages, "npm")

# Step 2 — Build graph
builder  = GraphBuilder()
G        = builder.build(result)

# Step 3 — Enrich with CVEs
enricher = CVEEnricher()
G        = enricher.enrich(G, "npm")

# Step 4 — Show vulnerable nodes
print("\n🚨 Vulnerable Packages in Graph:")
vuln_nodes = [
    (n, d) for n, d in G.nodes(data=True) if d["has_cve"]
]

if not vuln_nodes:
    print("  No vulnerabilities found")
else:
    for node_id, data in vuln_nodes:
        print(f"\n  Package  : {node_id}")
        print(f"  CVSS Max : {data['cvss_max']} ({enricher._cvss_to_severity(data['cvss_max'])})")
        print(f"  CVEs     :")
        for cve in data["cve_list"][:3]:   # show first 3
            print(f"    - {cve['id']} | {cve['severity']} | {cve['summary'][:60]}")