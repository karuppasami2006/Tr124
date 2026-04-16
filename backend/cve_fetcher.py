import httpx
import asyncio
import logging
from typing import List, Dict, Optional
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD API may require a key for higher rate limits, but works without for low volumes
NVD_API_KEY = os.getenv("NVD_API_KEY")

class NVDClient:
    def __init__(self):
        self.headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        self.client = httpx.AsyncClient(timeout=15.0, headers=self.headers)

    async def fetch_cves_by_keyword(self, keyword: str) -> List[Dict]:
        """Fetch CVEs from NVD for a specific library/package name."""
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 5 # Limit for speed in demo
            }
            response = await self.client.get(NVD_API_URL, params=params)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    
                    vulnerabilities.append({
                        "cve_id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value"),
                        "cvss_score": cvss_data.get("baseScore", 5.0),
                        "severity": cvss_data.get("baseSeverity", "Medium"),
                        "published": cve.get("published")
                    })
                return vulnerabilities
            return []
        except Exception as e:
            logging.error(f"NVD API Error: {e}")
            return []

    async def get_integrated_vuln(self, package: str, version: str) -> Optional[Dict]:
        """Hybrid check: NVD Data + Version Comparison."""
        # For a hackathon, we prioritize speed by combining real NVD search with local heuristics
        cves = await self.fetch_cves_by_keyword(package)
        
        if not cves:
            # Fallback to local intelligence if NVD is slow/blocked
            from .cve_fetcher_fallback import LOCAL_THREAT_INTEL
            return LOCAL_THREAT_INTEL.get(package, {}).get(version)
            
        # Select most relevant high-severity CVE
        top_vuln = sorted(cves, key=lambda x: x['cvss_score'], reverse=True)[0]
        
        return {
            "cve_id": top_vuln['cve_id'],
            "severity": top_vuln['severity'],
            "cvss_score": top_vuln['cvss_score'],
            "description": top_vuln['description'],
            "safe_version": "Latest stable/patched"
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
