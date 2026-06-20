import networkx as nx
from collections import deque


class PropagationSimulator:
    """
    Core novelty of the project.

    For every vulnerable node (has_cve = True):
        1. Reverse the graph (edges now point from dep → dependent)
        2. Run BFS from that node
        3. Find every package that depends on it (directly or transitively)
        4. Record hop distance from CVE node to each affected package
        5. Compute Blast Radius = total affected packages

    Then compute Risk Score per node:
        RiskScore = CVSS_score × (1 / hop_distance) × 
                    dependent_count × pagerank_weight

    Final output = ranked list of all packages by risk score
    """

    def __init__(self):
        self.propagation_results = {}   # cve_node → propagation data
        self.node_risk_scores    = {}   # node_id  → final risk score

    def simulate(self, G: nx.DiGraph) -> dict:
        """
        Main entry point.
        Takes enriched graph, runs full propagation simulation.

        Returns:
        {
            "total_cve_nodes": 3,
            "total_affected_nodes": 12,
            "propagation": {
                "lodash@4.17.20": {
                    "blast_radius": 5,
                    "affected_nodes": [...],
                    ...
                }
            },
            "risk_ranking": [
                {"node_id": "express@4.18.2", "risk_score": 8.4, ...},
                ...
            ]
        }
        """
        # Get all vulnerable nodes
        cve_nodes = [
            n for n, d in G.nodes(data=True) if d.get("has_cve")
        ]

        print(f"\n🔥 Starting Propagation Simulation")
        print(f"   CVE nodes found : {len(cve_nodes)}")
        print(f"   Total nodes     : {G.number_of_nodes()}\n")

        if not cve_nodes:
            print("   No CVE nodes found — nothing to propagate")
            return {}

        # Reverse graph — edges now point FROM dependency TO dependent
        # If A → B (A depends on B), reversed gives B → A
        # So BFS from B finds all packages that depend on B
        G_reversed = G.reverse(copy=True)

        # Run propagation from each CVE node
        for cve_node in cve_nodes:
            self._propagate_from_node(G, G_reversed, cve_node)

        # Compute final risk scores for ALL nodes
        self._compute_risk_scores(G)

        # Build ranked list
        risk_ranking = self._build_risk_ranking(G)

        # Summary stats
        all_affected = set()
        for data in self.propagation_results.values():
            all_affected.update(data["affected_nodes"])

        print(f"\n📊 Propagation Summary:")
        print(f"   CVE nodes          : {len(cve_nodes)}")
        print(f"   Total affected     : {len(all_affected)}")
        print(f"   Clean nodes        : {G.number_of_nodes() - len(all_affected)}")

        return {
            "total_cve_nodes"     : len(cve_nodes),
            "total_affected_nodes": len(all_affected),
            "propagation"         : self.propagation_results,
            "risk_ranking"        : risk_ranking
        }

    # ── BFS PROPAGATION ───────────────────────────────────────
    def _propagate_from_node(self, G: nx.DiGraph,
                              G_reversed: nx.DiGraph,
                              cve_node: str):
        """
        Runs BFS from cve_node in REVERSED graph.
        Finds all packages that transitively depend on cve_node.
        Records hop distance for each.
        """
        node_data  = G.nodes[cve_node]
        cvss_score = node_data.get("cvss_max", 5.0)

        print(f"  💥 Propagating from: {cve_node}")
        print(f"     CVSS Score : {cvss_score}")

        # BFS with hop distance tracking
        visited  = {}       # node_id → hop_distance
        queue    = deque()

        # Start from CVE node itself (hop distance 0)
        queue.append((cve_node, 0))
        visited[cve_node] = 0

        while queue:
            current_node, hop = queue.popleft()

            # Explore neighbors in reversed graph
            for neighbor in G_reversed.neighbors(current_node):
                if neighbor not in visited:
                    visited[neighbor] = hop + 1
                    queue.append((neighbor, hop + 1))

        # Remove the CVE node itself from affected list
        affected = {
            node: hop for node, hop in visited.items()
            if node != cve_node
        }

        blast_radius = len(affected)

        print(f"     Blast Radius : {blast_radius} packages affected")
        for node, hop in sorted(affected.items(), key=lambda x: x[1]):
            print(f"       hop {hop} → {node}")

        # Store propagation result
        self.propagation_results[cve_node] = {
            "cve_node"        : cve_node,
            "cvss_score"      : cvss_score,
            "blast_radius"    : blast_radius,
            "affected_nodes"  : list(affected.keys()),
            "hop_distances"   : affected,    # node → hop distance
            "cve_list"        : node_data.get("cve_list", [])
        }

    # ── RISK SCORE FORMULA ────────────────────────────────────
    def _compute_risk_scores(self, G: nx.DiGraph):
        """
        Computes Risk Score for every node.

        Formula (your novel contribution):
        RiskScore(node) = Σ over all CVE sources affecting this node:
            CVSS_score × (1 / hop_distance) × dependent_count 
            × pagerank_weight

        A node's score accumulates from ALL CVEs that affect it.
        """
        print(f"\n⚙️  Computing Risk Scores...")

        for node_id in G.nodes():
            total_risk      = 0.0
            node_data       = G.nodes[node_id]
            dependent_count = node_data.get("dependent_count", 0) + 1
            pagerank        = node_data.get("pagerank", 0.001)

            # Check if this node is affected by any CVE propagation
            for cve_node, prop_data in self.propagation_results.items():

                # Case 1: This node IS the CVE node
                if node_id == cve_node:
                    cvss        = prop_data["cvss_score"]
                    hop         = 1   # treat source as hop 1
                    risk_contrib = cvss * (1.0 / hop) * dependent_count * (1 + pagerank * 10)
                    total_risk  += risk_contrib

                # Case 2: This node is affected by this CVE
                elif node_id in prop_data["hop_distances"]:
                    hop  = prop_data["hop_distances"][node_id]
                    cvss = prop_data["cvss_score"]

                    if hop == 0:
                        hop = 1  # avoid division by zero

                    risk_contrib = cvss * (1.0 / hop) * dependent_count * (1 + pagerank * 10)
                    total_risk  += risk_contrib

            # Round and store
            G.nodes[node_id]["risk_score"] = round(total_risk, 4)
            self.node_risk_scores[node_id] = round(total_risk, 4)

    # ── RISK RANKING ──────────────────────────────────────────
    def _build_risk_ranking(self, G: nx.DiGraph) -> list:
        """
        Builds sorted list of all nodes by risk score.
        Highest risk first = fix this first.
        """
        ranking = []

        for node_id, data in G.nodes(data=True):
            risk = data.get("risk_score", 0.0)
            if risk > 0:
                ranking.append({
                    "node_id"        : node_id,
                    "name"           : data["name"],
                    "version"        : data["version"],
                    "risk_score"     : risk,
                    "has_cve"        : data.get("has_cve", False),
                    "cvss_max"       : data.get("cvss_max", 0.0),
                    "dependent_count": data.get("dependent_count", 0),
                    "pagerank"       : data.get("pagerank", 0.0),
                    "cve_count"      : len(data.get("cve_list", [])),
                    "fix_priority"   : 0   # assigned below
                })

        # Sort by risk score descending
        ranking.sort(key=lambda x: x["risk_score"], reverse=True)

        # Assign fix priority rank
        for i, item in enumerate(ranking):
            item["fix_priority"] = i + 1

        return ranking