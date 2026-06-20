# save as backend/tests/test_nvd.py
import requests
import os
from dotenv import load_dotenv

load_dotenv()

def test_nvd(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.getenv("NVD_API_KEY")}
    params = {"cveId": cve_id}

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    cve = data["vulnerabilities"][0]["cve"]
    print(f"\nCVE ID   : {cve['id']}")
    print(f"Published: {cve['published']}")

    # get CVSS score
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        print(f"CVSS Score : {score}")
        print(f"Severity   : {severity}")

# Test with Log4Shell — the most famous CVE
test_nvd("CVE-2021-44228")