from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from scanner import HybridScanner
import cve_loader
from datetime import datetime

app = FastAPI(title="SecureFlow AI Enterprise API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (Simplification for hackathon/demo)
audit_logs = []
pr_comments = []
system_config = {
    "scan_depth": "medium",
    "ai_mode": "balanced",
    "auto_fix": True
}

class ScanRequest(BaseModel):
    code_diff: str
    language: str
    dependency_content: Optional[str] = None
    dependency_type: Optional[str] = "requirements"

class ConfigUpdateRequest(BaseModel):
    scan_depth: str
    ai_mode: str
    auto_fix: bool

scanner = HybridScanner()

@app.get("/cves/top")
def get_top_cves():
    return cve_loader.get_top_cves()

@app.get("/cves/{cve_id}")
async def get_cve_detail(cve_id: str):
    data = cve_loader.get_cve_from_local(cve_id)
    if not data:
        from cve_fetcher import NVDClient
        async with NVDClient() as client:
            results = await client.fetch_cves_by_keyword(cve_id)
            if results:
                return results[0]
            raise HTTPException(status_code=404, detail="CVE not found in local DB or NVD.")
    
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
        
        # 1. Update Audit Logs
        summary = result["scan_summary"]
        audit_logs.insert(0, {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "issues": summary["total_issues"],
            "critical": summary["critical"],
            "high": summary["high"],
            "status": summary["ci_status"]
        })

        # 2. Update PR Comments
        new_comments = []
        for v in result["vulnerabilities"]:
            new_comments.append({
                "file": v.get("file_or_package", "main.py"),
                "line": 42,
                "issue": v.get("title") or v.get("file_or_package"),
                "severity": v["severity"],
                "comment": f"🚨 **Security Alert**: {v.get('explanation', 'Exposure detected.')}\n\n"
                           f"**Vector**: {v.get('root_cause', 'Injection Point')}\n\n"
                           f"**Recommendation**: `{v.get('solution', 'Patch and Verify')}`"
            })
        
        # Clear and replace or append - replacing for "latest" feel
        global pr_comments
        pr_comments = new_comments

        return result
    except Exception as e:
        print(f"Scan API Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/pr-comments")
def get_pr_comments():
    # Provide sample if empty for demo
    if not pr_comments:
        return [
            {
                "file": "audit_engine.py",
                "line": 12,
                "issue": "Hardcoded API Key",
                "severity": "Critical",
                "comment": "🚨 **Security Alert**: Detected hardcoded credentials in source code. This is a severe security risk that leads to total system compromise.\n\n**Remediation**: Use environment variables or a secure Secret Manager."
            }
        ]
    return pr_comments

@app.get("/audit-logs")
def get_audit_logs():
    if not audit_logs:
        return [
            {"time": "2026-04-16 10:30", "issues": 3, "critical": 1, "high": 2, "status": "FAIL"},
            {"time": "2026-04-16 09:15", "issues": 0, "critical": 0, "high": 0, "status": "PASS"}
        ]
    return audit_logs[:10] # Return last 10

@app.get("/config")
def get_config():
    return system_config

@app.post("/config")
def update_config(req: ConfigUpdateRequest):
    global system_config
    system_config = req.dict()
    return {"status": "success", "config": system_config}

@app.get("/health")
def health():
    return {"status": "operational", "engine": "Hybrid SecureFlow v3.0"}
