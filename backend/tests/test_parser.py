import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.parser.dependency_parser import DependencyParser

parser = DependencyParser()

# ── TEST 1: NPM ────────────────────────────────────────────
print("=" * 50)
print("TEST 1 — NPM package.json")
print("=" * 50)

result = parser.parse("data/samples/sample_package.json")
print(f"Ecosystem     : {result['ecosystem']}")
print(f"Total Direct  : {result['total_direct']}")
print(f"\nPackages found:")
for pkg in result['packages']:
    print(f"  {pkg['name']:20} → {pkg['version']}")

# ── TEST 2: PYPI ───────────────────────────────────────────
print("\n" + "=" * 50)
print("TEST 2 — PyPI requirements.txt")
print("=" * 50)

result = parser.parse("data/samples/sample_requirements.txt")
print(f"Ecosystem     : {result['ecosystem']}")
print(f"Total Direct  : {result['total_direct']}")
print(f"\nPackages found:")
for pkg in result['packages']:
    print(f"  {pkg['name']:20} → {pkg['version']}")

print("\n✅ Parser working correctly")