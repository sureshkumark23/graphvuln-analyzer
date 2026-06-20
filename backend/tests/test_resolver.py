import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.parser.dependency_parser import DependencyParser
from backend.graph.resolver import TransitiveDependencyResolver

# ── TEST 1: NPM ────────────────────────────────────────────
print("=" * 55)
print("TEST — NPM Transitive Resolution (express only)")
print("=" * 55)

# Use just express to keep output short
packages = [{"name": "express", "version": "4.18.2"}]

resolver = TransitiveDependencyResolver(max_depth=2)
result   = resolver.resolve(packages, "npm")

print(f"\n📦 Total packages found : {result['total_packages']}")
print(f"🔗 Total edges          : {result['total_edges']}")
print(f"\nFirst 10 packages discovered:")
for i, (node_id, info) in enumerate(result['packages'].items()):
    if i >= 10:
        print("  ...")
        break
    print(f"  [{info['depth']}] {node_id}")