from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from .scanner import HybridScanner

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
    dependency_type: Optional[str] = "requirements" # requirements or package.json

scanner = HybridScanner()

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
