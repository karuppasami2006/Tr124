from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from scanner import HybridScanner
import cve_loader

app = FastAPI(title="SecureFlow AI Enterprise API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    code_diff: str
    language: str
    dependency_content: Optional[str] = None
    dependency_type: Optional[str] = "requirements"

scanner = HybridScanner()

@app.get("/cves/top")
def get_top_cves():
    return cve_loader.get_top_cves()

@app.get("/cves/{cve_id}")
async def get_cve_detail(cve_id: str):
    data = cve_loader.get_cve_from_local(cve_id)
    if not data:
        # Fallback to NVD via scanner's client
        from cve_fetcher import NVDClient
        async with NVDClient() as client:
            # We use keyword search for the CVE ID directly
            results = await client.fetch_cves_by_keyword(cve_id)
            if results:
                return results[0]
            raise HTTPException(status_code=404, detail="CVE not found in local DB or NVD.")
    
    # Enrichment
    enriched = await cve_loader.enrich_cve_data(data, scanner.ai)
    return enriched

@app.post("/scan")
async def run_scan(request: ScanRequest):
    try:
        result = await scanner.scan(
            request.code_diff, 
            request.dependency_content,
            request.dependency_type
        )
        return result
    except Exception as e:
        print(f"Scan API Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "operational", "engine": "Hybrid SecureFlow v3.0"}
