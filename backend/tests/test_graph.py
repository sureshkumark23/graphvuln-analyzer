# save as backend/tests/test_graph.py
import networkx as nx

# Create a directed graph
G = nx.DiGraph()

# Add nodes (packages)
G.add_node("your-app")
G.add_node("express")
G.add_node("lodash")
G.add_node("accepts")
G.add_node("mime-types")   # ← this has CVE

# Add edges (A depends on B)
G.add_edge("your-app", "express")
G.add_edge("express", "lodash")
G.add_edge("express", "accepts")
G.add_edge("accepts", "mime-types")
G.add_edge("lodash", "mime-types")

print(f"Total packages : {G.number_of_nodes()}")
print(f"Total edges    : {G.number_of_edges()}")

# BFS from vulnerable node (mime-types)
# Find all packages that DEPEND on mime-types
# We reverse the graph — so edges point from dependency TO dependent
G_reversed = G.reverse()

affected = list(nx.bfs_tree(G_reversed, "mime-types").nodes())
print(f"\nIf mime-types has CVE, affected packages:")
for pkg in affected:
    print(f"  → {pkg}")

# Hop distance from mime-types to each affected node
distances = nx.single_source_shortest_path_length(G_reversed, "mime-types")
print(f"\nHop distances:")
for pkg, dist in distances.items():
    print(f"  {pkg} : {dist} hops away")