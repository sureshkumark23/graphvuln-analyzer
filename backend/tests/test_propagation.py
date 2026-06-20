import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.graph.resolver import TransitiveDependencyResolver
from backend.graph.graph_builder import GraphBuilder
from backend.cve.cve_enricher import CVEEnricher
from backend.propagation.propagation_simulator import PropagationSimulator

print("=" * 60)
print("TEST — Propagation Simulator + Risk Scoring")
print("=" * 60)

# Step 1 — Resolve
packages = [
    {"name": "lodash",  "version": "4.17.20"},
    {"name": "express", "version": "4.18.2"}
]
resolver = TransitiveDependencyResolver(max_depth=1)
result   = resolver.resolve(packages, "npm")

# Step 2 — Build graph
builder  = GraphBuilder()
G        = builder.build(result)

# Step 3 — Enrich CVEs (uses cache — instant now)
enricher = CVEEnricher()
G        = enricher.enrich(G, "npm")

# Step 4 — Simulate propagation
simulator = PropagationSimulator()
output    = simulator.simulate(G)

# Step 5 — Print Fix Priority Ranking
print("\n" + "=" * 60)
print("🏆 FIX PRIORITY RANKING (Fix #1 First)")
print("=" * 60)
print(f"{'Rank':<6} {'Package':<35} {'Risk Score':<12} "
      f"{'CVSS':<8} {'CVEs':<6} {'Dependents'}")
print("-" * 80)

for pkg in output["risk_ranking"]:
    cve_flag = "🚨" if pkg["has_cve"] else "⚠️ "
    print(f"  #{pkg['fix_priority']:<4} "
          f"{cve_flag} {pkg['node_id']:<33} "
          f"{pkg['risk_score']:<12.4f} "
          f"{pkg['cvss_max']:<8} "
          f"{pkg['cve_count']:<6} "
          f"{pkg['dependent_count']}")

print(f"\n✅ Total packages with risk score : {len(output['risk_ranking'])}")
print(f"✅ Total CVE source nodes         : {output['total_cve_nodes']}")
print(f"✅ Total affected nodes           : {output['total_affected_nodes']}")