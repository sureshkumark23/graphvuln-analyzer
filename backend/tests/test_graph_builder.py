import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.graph.resolver import TransitiveDependencyResolver
from backend.graph.graph_builder import GraphBuilder

print("=" * 55)
print("TEST — Graph Builder")
print("=" * 55)

# Step 1 — Resolve dependencies
packages = [{"name": "express", "version": "4.18.2"}]
resolver = TransitiveDependencyResolver(max_depth=2)
result   = resolver.resolve(packages, "npm")

# Step 2 — Build graph
builder  = GraphBuilder()
G        = builder.build(result)

# Step 3 — Print stats
builder.print_stats()

# Step 4 — Spot check one node
print("\n🔍 Spot Check — express@4.18.2 node attributes:")
node = G.nodes["express@4.18.2"]
for key, val in node.items():
    print(f"  {key:20} : {val}")