import requests
import time
import sqlite3
import json
import os
from dotenv import load_dotenv
import urllib3
urllib3.disable_warnings()

load_dotenv()


class CVEEnricher:
    """
    Checks every node in the graph against OSV and NVD APIs.
    Attaches CVE data directly to graph nodes.

    Uses SQLite cache so we don't re-call APIs for same package.
    Cache lives in data/cve_cache.db
    """

    def __init__(self, cache_path: str = "data/cve_cache.db"):
        self.osv_url  = "https://api.osv.dev/v1/query"
        self.nvd_url  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_key  = os.getenv("NVD_API_KEY", "")
        self.cache_path = cache_path
        self._init_cache()

    # ── CACHE SETUP ───────────────────────────────────────────
    def _init_cache(self):
        """Creates SQLite cache table if not exists."""
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        conn = sqlite3.connect(self.cache_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                package_key TEXT PRIMARY KEY,
                cve_data    TEXT,
                cached_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def _get_cache(self, key: str):
        conn   = sqlite3.connect(self.cache_path)
        cursor = conn.execute(
            "SELECT cve_data FROM cve_cache WHERE package_key = ?", (key,)
        )
        row = cursor.fetchone()
        conn.close()
        return json.loads(row[0]) if row else None

    def _set_cache(self, key: str, data: list):
        conn = sqlite3.connect(self.cache_path)
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (package_key, cve_data) VALUES (?, ?)",
            (key, json.dumps(data))
        )
        conn.commit()
        conn.close()

    # ── MAIN ENRICHMENT ───────────────────────────────────────
    def enrich(self, G, ecosystem: str):
        """
        Iterates every node in graph G.
        For each node, fetches CVEs and attaches to node attributes.
        Modifies graph in place.
        """
        total    = G.number_of_nodes()
        enriched = 0
        cve_nodes = 0

        print(f"\n🔎 Enriching {total} packages with CVE data...")
        print(f"   (Using SQLite cache — first run will be slow)\n")

        for node_id, data in G.nodes(data=True):
            name      = data["name"]
            version   = data["version"]
            enriched += 1

            # Map ecosystem to OSV format
            osv_ecosystem = "npm" if ecosystem == "npm" else "PyPI"

            # Fetch CVEs
            cves = self._fetch_cves(name, version, osv_ecosystem)

            if cves:
                cve_nodes += 1
                # Get highest CVSS score among all CVEs for this package
                max_cvss  = max((c["cvss_score"] for c in cves), default=0.0)

                # Attach to graph node
                G.nodes[node_id]["has_cve"]   = True
                G.nodes[node_id]["cve_list"]  = cves
                G.nodes[node_id]["cvss_max"]  = max_cvss

                severity = self._cvss_to_severity(max_cvss)
                print(f"  🚨 {node_id:40} | {len(cves)} CVEs | "
                      f"Max CVSS: {max_cvss} ({severity})")
            else:
                print(f"  ✅ {node_id:40} | Clean")

            # Be polite to APIs
            time.sleep(0.2)

        print(f"\n📊 Enrichment Summary:")
        print(f"   Total packages checked : {enriched}")
        print(f"   Vulnerable packages    : {cve_nodes}")
        print(f"   Clean packages         : {enriched - cve_nodes}")

        return G

    # ── CVE FETCHER ───────────────────────────────────────────
    def _fetch_cves(self, name: str, version: str,
                    ecosystem: str) -> list:
        """
        Fetches CVEs from OSV API with SQLite cache.
        Returns list of CVE dicts.
        """
        cache_key = f"{ecosystem}:{name}:{version}"
        cached    = self._get_cache(cache_key)
        if cached is not None:
            return cached

        try:
            payload  = {
                "package": {
                    "name"      : name,
                    "ecosystem" : ecosystem
                },
                "version": version
            }
            response = requests.post(
                self.osv_url, json=payload, timeout=10
            )

            if response.status_code != 200:
                self._set_cache(cache_key, [])
                return []

            data = response.json()
            vulns = data.get("vulns", [])

            cves = []
            for v in vulns:
                cvss_score = self._extract_cvss(v)
                cves.append({
                    "id"         : v.get("id", "UNKNOWN"),
                    "summary"    : v.get("summary", "No summary"),
                    "cvss_score" : cvss_score,
                    "severity"   : self._cvss_to_severity(cvss_score),
                    "published"  : v.get("published", ""),
                })

            self._set_cache(cache_key, cves)
            return cves

        except Exception as e:
            print(f"  ⚠️  CVE fetch failed for {name}@{version}: {e}")
            self._set_cache(cache_key, [])
            return []

    def _extract_cvss(self, vuln: dict) -> float:
        """Extracts CVSS score from OSV vulnerability object."""
        # Try severity field first
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                try:
                    # CVSS vector string — extract base score
                    # Format: CVSS:3.1/AV:N/AC:L/... or just a number
                    if "/" in score_str:
                        # Parse from vector — use last number pattern
                        import re
                        nums = re.findall(r'\d+\.\d+', score_str)
                        if nums:
                            return float(nums[-1])
                    else:
                        return float(score_str)
                except:
                    pass

        # Try database_specific scores
        db_specific = vuln.get("database_specific", {})
        if "cvss" in db_specific:
            try:
                return float(db_specific["cvss"])
            except:
                pass

        # Default moderate score if CVE exists but no CVSS
        return 5.0

    def _cvss_to_severity(self, score: float) -> str:
        """Converts CVSS score to severity label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "NONE"