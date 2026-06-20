import json
import re
from pathlib import Path


class DependencyParser:
    """
    Parses dependency files and extracts package name + version.
    Supports: package.json (npm) and requirements.txt (PyPI)
    """

    def parse(self, file_path: str) -> dict:
        """
        Main entry point.
        Returns:
        {
            "ecosystem": "npm" or "pypi",
            "packages": [
                {"name": "lodash", "version": "4.17.20"},
                ...
            ]
        }
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if path.name.endswith("package.json"):
            return self._parse_npm(path)
        elif path.name.endswith("requirements.txt"):
            return self._parse_pypi(path)
        else:
            raise ValueError(f"Unsupported file: {path.name}. Use package.json or requirements.txt")

    # ── NPM PARSER ────────────────────────────────────────────
    def _parse_npm(self, path: Path) -> dict:
        with open(path, "r") as f:
            data = json.load(f)

        packages = []

        for section in ["dependencies", "devDependencies"]:
            deps = data.get(section, {})
            for name, version in deps.items():
                clean_version = self._clean_npm_version(version)
                packages.append({
                    "name": name,
                    "version": clean_version
                })

        return {
            "ecosystem": "npm",
            "source_file": str(path),
            "total_direct": len(packages),
            "packages": packages
        }

    def _clean_npm_version(self, version: str) -> str:
        """
        npm versions come as ^4.17.20 or ~1.2.3 or >=2.0.0
        We strip the prefix and return clean version like 4.17.20
        """
        clean = re.sub(r'^[\^~>=<]+', '', version.strip())
        clean = clean.split(' ')[0]
        clean = clean.replace('.x', '.0')
        if clean == '*' or clean == '':
            return 'latest'
        return clean

    # ── PYPI PARSER ───────────────────────────────────────────
    def _parse_pypi(self, path: Path) -> dict:
        packages = []

        with open(path, "r") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if line.startswith('-'):
                continue

            package = self._parse_pypi_line(line)
            if package:
                packages.append(package)

        return {
            "ecosystem": "pypi",
            "source_file": str(path),
            "total_direct": len(packages),
            "packages": packages
        }

    def _parse_pypi_line(self, line: str):
        """
        Handles formats:
        django==4.2.0
        django>=4.0
        django~=4.2
        django
        django[crypto]==4.2.0
        """
        line = line.split('#')[0].strip()
        line = re.sub(r'\[.*?\]', '', line)

        match = re.split(r'(==|>=|<=|~=|!=|>|<)', line, maxsplit=1)

        name = match[0].strip()
        version = match[2].strip() if len(match) >= 3 else 'latest'
        version = version.split(',')[0].strip()

        if not name:
            return None

        return {
            "name": name,
            "version": version
        }