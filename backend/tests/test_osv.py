# save as backend/tests/test_osv.py
import requests

def test_osv(package_name, ecosystem, version):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        },
        "version": version
    }
    response = requests.post(url, json=payload)
    data = response.json()

    if "vulns" in data:
        print(f"\n{len(data['vulns'])} vulnerabilities found in {package_name} {version}")
        for v in data["vulns"]:
            print(f"  ID     : {v['id']}")
            print(f"  Summary: {v.get('summary', 'N/A')}")
            print("---")
    else:
        print(f"No vulnerabilities found for {package_name} {version}")

# Test 1 — known vulnerable package
test_osv("lodash", "npm", "4.17.20")

# Test 2 — known vulnerable Python package
test_osv("django", "PyPI", "2.2.0")