import requests
import time
from typing import Optional

# Suppress SSL warning on Mac
import urllib3
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)


class TransitiveDependencyResolver:
    """
    Takes direct packages and recursively resolves ALL
    transitive dependencies using npm and PyPI registry APIs.

    Output is a flat list of ALL packages in the project
    (direct + transitive) with their relationships.
    """

    def __init__(self, max_depth: int = 8):
        self.max_depth   = max_depth
        self.npm_url     = "https://registry.npmjs.org"
        self.pypi_url    = "https://pypi.org/pypi"
        self.visited     = set()   # track already resolved packages
        self.edges       = []      # (parent, child) relationships
        self.all_packages = {}     # name@version → package info

    def resolve(self, packages: list, ecosystem: str) -> dict:
        """
        Main entry point.
        packages  = [{"name": "lodash", "version": "4.17.20"}, ...]
        ecosystem = "npm" or "pypi"

        Returns:
        {
            "total_packages": 42,
            "edges": [("express", "lodash"), ...],
            "packages": {"lodash@4.17.20": {...}, ...}
        }
        """
        self.visited      = set()
        self.edges        = []
        self.all_packages = {}

        print(f"\n🔍 Resolving {len(packages)} direct dependencies...")
        print(f"   Ecosystem : {ecosystem}")
        print(f"   Max depth : {self.max_depth}\n")

        for pkg in packages:
            name    = pkg["name"]
            version = pkg["version"]
            self._resolve_recursive(name, version, ecosystem, depth=0, parent=None)

        print(f"\n✅ Resolution complete")
        print(f"   Total unique packages : {len(self.all_packages)}")
        print(f"   Total edges           : {len(self.edges)}")

        return {
            "ecosystem"      : ecosystem,
            "total_packages" : len(self.all_packages),
            "total_edges"    : len(self.edges),
            "edges"          : self.edges,
            "packages"       : self.all_packages
        }

    # ── RECURSIVE RESOLVER ────────────────────────────────────
    def _resolve_recursive(self, name: str, version: str,
                           ecosystem: str, depth: int, parent: Optional[str]):

        if depth > self.max_depth:
            return

        node_id = f"{name}@{version}"

        # Add edge from parent to this package
        if parent:
            edge = (parent, node_id)
            if edge not in self.edges:
                self.edges.append(edge)

        # Already visited — skip fetching but edge already added
        if node_id in self.visited:
            return

        self.visited.add(node_id)

        # Store package info
        self.all_packages[node_id] = {
            "name"      : name,
            "version"   : version,
            "ecosystem" : ecosystem,
            "depth"     : depth
        }

        print(f"  {'  ' * depth}→ {node_id} (depth {depth})")

        # Fetch dependencies of this package
        if ecosystem == "npm":
            deps = self._fetch_npm_deps(name, version)
        else:
            deps = self._fetch_pypi_deps(name, version)

        # Recurse into each dependency
        for dep_name, dep_version in deps.items():
            self._resolve_recursive(
                dep_name, dep_version,
                ecosystem, depth + 1, node_id
            )

    # ── NPM FETCHER ───────────────────────────────────────────
    def _fetch_npm_deps(self, name: str, version: str) -> dict:
        try:
            url      = f"{self.npm_url}/{name}/{version}"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                # Try without version — get latest
                url      = f"{self.npm_url}/{name}/latest"
                response = requests.get(url, timeout=10)

            if response.status_code != 200:
                return {}

            data = response.json()
            deps = data.get("dependencies", {})

            # Clean versions
            cleaned = {}
            for dep_name, dep_version in deps.items():
                clean = dep_version.strip()
                clean = clean.lstrip("^~>=<")
                clean = clean.split(" ")[0]
                clean = clean.replace(".x", ".0")
                if clean and clean != "*":
                    cleaned[dep_name] = clean
                else:
                    cleaned[dep_name] = "latest"

            time.sleep(0.1)  # be polite to npm registry
            return cleaned

        except Exception as e:
            print(f"  ⚠️  npm fetch failed for {name}@{version}: {e}")
            return {}

    # ── PYPI FETCHER ──────────────────────────────────────────
    def _fetch_pypi_deps(self, name: str, version: str) -> dict:
        try:
            if version == "latest":
                url = f"{self.pypi_url}/{name}/json"
            else:
                url = f"{self.pypi_url}/{name}/{version}/json"

            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                url      = f"{self.pypi_url}/{name}/json"
                response = requests.get(url, timeout=10)

            if response.status_code != 200:
                return {}

            data     = response.json()
            requires = data.get("info", {}).get("requires_dist") or []

            cleaned = {}
            for req in requires:
                # Format: "Django>=2.0", "requests ; extra=='test'"
                # Skip optional extras
                if "extra ==" in req or 'extra=="' in req:
                    continue

                # Remove environment markers like ; python_version
                req = req.split(";")[0].strip()

                # Parse name and version
                parts = req.split()
                if not parts:
                    continue

                dep_name    = parts[0].strip()
                dep_version = "latest"

                if len(parts) > 1:
                    ver_str     = parts[1].strip()
                    dep_version = ver_str.lstrip(">=<~!=").split(",")[0]
                    if not dep_version:
                        dep_version = "latest"

                cleaned[dep_name] = dep_version

            time.sleep(0.1)  # be polite to PyPI
            return cleaned

        except Exception as e:
            print(f"  ⚠️  PyPI fetch failed for {name}@{version}: {e}")
            return {}