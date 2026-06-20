import networkx as nx
from typing import Optional


class GraphBuilder:
    """
    Takes resolver output and builds a NetworkX directed graph.

    Node = package (name@version)
    Edge = A → B means "A depends on B"

    Also computes:
    - Depth of each node
    - Number of dependents per node (in-degree in reversed graph)
    - PageRank score per node
    """

    def __init__(self):
        self.graph     = None
        self.ecosystem = None

    def build(self, resolver_output: dict) -> nx.DiGraph:
        """
        Main entry point.
        Takes resolver output dict and returns a NetworkX DiGraph.
        """
        self.ecosystem = resolver_output["ecosystem"]
        packages       = resolver_output["packages"]
        edges          = resolver_output["edges"]

        # Create directed graph
        G = nx.DiGraph()

        # Add all nodes with attributes
        for node_id, info in packages.items():
            G.add_node(node_id,
                name       = info["name"],
                version    = info["version"],
                ecosystem  = info["ecosystem"],
                depth      = info["depth"],
                has_cve    = False,      # will be set in CVE enrichment
                cve_list   = [],         # will be filled in CVE enrichment
                cvss_max   = 0.0,        # highest CVSS score among CVEs
                risk_score = 0.0         # will be computed in propagation
            )

        # Add all edges
        for parent, child in edges:
            if G.has_node(parent) and G.has_node(child):
                G.add_edge(parent, child)

        # Compute PageRank — measures how "central" each package is
        pagerank = nx.pagerank(G, alpha=0.85)
        for node_id, score in pagerank.items():
            G.nodes[node_id]["pagerank"] = round(score, 6)

        # Compute dependent count — how many packages depend on this one
        # Use reversed graph: if A→B, then in reversed graph B→A
        G_rev = G.reverse()
        for node_id in G.nodes():
            # All nodes reachable from node_id in reversed graph
            # = all packages that depend on node_id
            dependents = len(nx.descendants(G_rev, node_id))
            G.nodes[node_id]["dependent_count"] = dependents

        self.graph = G
        return G

    def get_stats(self) -> dict:
        """Returns summary statistics about the graph."""
        if not self.graph:
            return {}

        G = self.graph

        # Find root nodes (no incoming edges = top level packages)
        roots = [n for n in G.nodes() if G.in_degree(n) == 0]

        # Find leaf nodes (no outgoing edges = no dependencies)
        leaves = [n for n in G.nodes() if G.out_degree(n) == 0]

        return {
            "total_nodes"     : G.number_of_nodes(),
            "total_edges"     : G.number_of_edges(),
            "root_packages"   : len(roots),
            "leaf_packages"   : len(leaves),
            "is_dag"          : nx.is_directed_acyclic_graph(G),
            "avg_depth"       : round(
                sum(G.nodes[n]["depth"] for n in G.nodes()) / G.number_of_nodes(), 2
            ),
            "most_depended_on": sorted(
                G.nodes(data=True),
                key=lambda x: x[1]["dependent_count"],
                reverse=True
            )[:5]   # top 5 most depended-on packages
        }

    def print_stats(self):
        """Prints a clean summary of the graph."""
        stats = self.get_stats()
        G     = self.graph

        print("\n" + "=" * 55)
        print("📊 GRAPH STATISTICS")
        print("=" * 55)
        print(f"  Total nodes (packages) : {stats['total_nodes']}")
        print(f"  Total edges            : {stats['total_edges']}")
        print(f"  Root packages          : {stats['root_packages']}")
        print(f"  Leaf packages          : {stats['leaf_packages']}")
        print(f"  Is valid DAG           : {stats['is_dag']}")
        print(f"  Average depth          : {stats['avg_depth']}")

        print(f"\n  🏆 Top 5 Most Depended-On Packages:")
        for node_id, data in stats["most_depended_on"]:
            print(f"    {node_id:35} → {data['dependent_count']} dependents"
                  f"  (PageRank: {data['pagerank']})")