import sys
import os
import pytest
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

import networkx as nx
from backend.parser.dependency_parser import DependencyParser
from backend.graph.graph_builder import GraphBuilder
from backend.propagation.propagation_simulator import PropagationSimulator

# ═══════════════════════════════════════════════════════════
# PARSER TESTS
# ═══════════════════════════════════════════════════════════

class TestDependencyParser:

    def setup_method(self):
        self.parser = DependencyParser()

    # Test 1
    def test_npm_returns_correct_ecosystem(self):
        result = self.parser.parse("data/samples/sample_package.json")
        assert result["ecosystem"] == "npm"

    # Test 2
    def test_npm_returns_correct_package_count(self):
        result = self.parser.parse("data/samples/sample_package.json")
        assert result["total_direct"] == 6

    # Test 3
    def test_npm_lodash_version_cleaned(self):
        result = self.parser.parse("data/samples/sample_package.json")
        lodash = next(p for p in result["packages"] if p["name"] == "lodash")
        # ^4.17.20 should become 4.17.20
        assert lodash["version"] == "4.17.20"
        assert "^" not in lodash["version"]

    # Test 4
    def test_npm_express_found(self):
        result = self.parser.parse("data/samples/sample_package.json")
        names = [p["name"] for p in result["packages"]]
        assert "express" in names

    # Test 5
    def test_pypi_returns_correct_ecosystem(self):
        result = self.parser.parse("data/samples/sample_requirements.txt")
        assert result["ecosystem"] == "pypi"

    # Test 6
    def test_pypi_returns_correct_package_count(self):
        result = self.parser.parse("data/samples/sample_requirements.txt")
        assert result["total_direct"] == 7

    # Test 7
    def test_pypi_django_version_correct(self):
        result = self.parser.parse("data/samples/sample_requirements.txt")
        django = next(p for p in result["packages"] if p["name"] == "django")
        assert django["version"] == "4.2.0"

    # Test 8
    def test_file_not_found_raises_error(self):
        with pytest.raises(FileNotFoundError):
            self.parser.parse("nonexistent_file.json")

    # Test 9
    def test_unsupported_file_raises_error(self):
        # Create a temp unsupported file
        with open("/tmp/setup.py", "w") as f:
            f.write("# setup file")
        with pytest.raises(ValueError):
            self.parser.parse("/tmp/setup.py")


# ═══════════════════════════════════════════════════════════
# GRAPH BUILDER TESTS
# ═══════════════════════════════════════════════════════════

class TestGraphBuilder:

    def setup_method(self):
        self.builder = GraphBuilder()
        # Build a small mock graph
        self.mock_resolver_output = {
            "ecosystem": "npm",
            "packages": {
                "express@4.18.2": {
                    "name": "express", "version": "4.18.2",
                    "ecosystem": "npm", "depth": 0
                },
                "lodash@4.17.20": {
                    "name": "lodash", "version": "4.17.20",
                    "ecosystem": "npm", "depth": 1
                },
                "mime-types@2.1.35": {
                    "name": "mime-types", "version": "2.1.35",
                    "ecosystem": "npm", "depth": 2
                },
            },
            "edges": [
                ("express@4.18.2", "lodash@4.17.20"),
                ("express@4.18.2", "mime-types@2.1.35"),
            ]
        }

    # Test 10
    def test_graph_has_correct_node_count(self):
        G = self.builder.build(self.mock_resolver_output)
        assert G.number_of_nodes() == 3

    # Test 11
    def test_graph_has_correct_edge_count(self):
        G = self.builder.build(self.mock_resolver_output)
        assert G.number_of_edges() == 2

    # Test 12
    def test_graph_is_directed(self):
        G = self.builder.build(self.mock_resolver_output)
        assert isinstance(G, nx.DiGraph)

    # Test 13
    def test_node_has_required_attributes(self):
        G = self.builder.build(self.mock_resolver_output)
        node = G.nodes["express@4.18.2"]
        assert "has_cve"        in node
        assert "risk_score"     in node
        assert "pagerank"       in node
        assert "dependent_count" in node

    # Test 14
    def test_graph_is_valid_dag(self):
        G = self.builder.build(self.mock_resolver_output)
        assert nx.is_directed_acyclic_graph(G)


# ═══════════════════════════════════════════════════════════
# PROPAGATION SIMULATOR TESTS
# ═══════════════════════════════════════════════════════════

class TestPropagationSimulator:

    def setup_method(self):
        self.simulator = PropagationSimulator()

    def _build_test_graph(self):
        """Build a small graph with one CVE node for testing."""
        G = nx.DiGraph()

        # App → express → lodash (has CVE) → mime-types
        G.add_node("app@1.0.0",
            name="app", version="1.0.0", depth=0,
            has_cve=False, cve_list=[], cvss_max=0.0,
            risk_score=0.0, pagerank=0.01, dependent_count=0
        )
        G.add_node("express@4.18.2",
            name="express", version="4.18.2", depth=1,
            has_cve=False, cve_list=[], cvss_max=0.0,
            risk_score=0.0, pagerank=0.02, dependent_count=1
        )
        G.add_node("lodash@4.17.20",
            name="lodash", version="4.17.20", depth=2,
            has_cve=True,
            cve_list=[{
                "id": "GHSA-35jh-r3h4-6jhm",
                "summary": "Command Injection",
                "cvss_score": 7.2,
                "severity": "HIGH"
            }],
            cvss_max=7.2,
            risk_score=0.0, pagerank=0.015, dependent_count=2
        )
        G.add_node("mime-types@2.1.35",
            name="mime-types", version="2.1.35", depth=3,
            has_cve=False, cve_list=[], cvss_max=0.0,
            risk_score=0.0, pagerank=0.008, dependent_count=3
        )

        G.add_edge("app@1.0.0",      "express@4.18.2")
        G.add_edge("express@4.18.2", "lodash@4.17.20")
        G.add_edge("lodash@4.17.20", "mime-types@2.1.35")

        return G

    # Test 15
    def test_propagation_finds_cve_node(self):
        G = self._build_test_graph()
        output = self.simulator.simulate(G)
        assert output["total_cve_nodes"] == 1

    # Test 16
    def test_blast_radius_correct(self):
        G = self._build_test_graph()
        output = self.simulator.simulate(G)
        # lodash affects express and app (2 packages above it)
        blast = output["propagation"]["lodash@4.17.20"]["blast_radius"]
        assert blast == 2

    # Test 17
    def test_affected_nodes_correct(self):
        G = self._build_test_graph()
        output = self.simulator.simulate(G)
        affected = output["propagation"]["lodash@4.17.20"]["affected_nodes"]
        assert "express@4.18.2" in affected
        assert "app@1.0.0"      in affected
        # mime-types is BELOW lodash, not above — should NOT be affected
        assert "mime-types@2.1.35" not in affected

    # Test 18
    def test_risk_score_computed_for_cve_node(self):
        G = self._build_test_graph()
        self.simulator.simulate(G)
        # lodash has CVE — should have non-zero risk score
        assert G.nodes["lodash@4.17.20"]["risk_score"] > 0

    # Test 19
    def test_risk_ranking_sorted_descending(self):
        G = self._build_test_graph()
        output = self.simulator.simulate(G)
        scores = [pkg["risk_score"] for pkg in output["risk_ranking"]]
        assert scores == sorted(scores, reverse=True)

    # Test 20
    def test_clean_node_has_zero_risk(self):
        G = self._build_test_graph()
        self.simulator.simulate(G)
        # mime-types is below CVE node — not affected
        assert G.nodes["mime-types@2.1.35"]["risk_score"] == 0.0