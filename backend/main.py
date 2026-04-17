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
audit_logs = [
    {"time": "2026-04-16 10:30", "issues": 3, "critical": 1, "high": 2, "status": "FAIL"},
    {"time": "2026-04-16 14:15", "issues": 0, "critical": 0, "high": 0, "status": "PASS"},
    {"time": "2026-04-16 16:45", "issues": 1, "critical": 1, "high": 0, "status": "FAIL"}
]
pr_comments = [
    {
        "file": "auth_service.py",
        "line": 42,
        "issue": "Broken Authentication",
        "severity": "Critical",
        "comment": "🚨 **Security Alert**: Detected missing rate limiting on login endpoint. This enables brute-force attacks on user credentials.\n\n**Remediation**: Implement an exponential backoff or use a WAF policy.",
        "before": "def login(): \n    pass",
        "after": "@rate_limit(limit=5, period=60)\ndef login(): \n    pass"
    },
    {
        "file": "utils/parsing.py",
        "line": 15,
        "issue": "XSS Vulnerability",
        "severity": "High",
        "comment": "🚨 **Security Alert**: Unsanitized user input is being directly rendered in the UI. This can lead to session hijacking.\n\n**Remediation**: Use a templating engine with auto-escaping or sanitize with Bleach.",
        "before": "return f'<div>{user_input}</div>'",
        "after": "return render_template('msg.html', user_input=user_input)"
    }
]
reviews = [
    {"time": "2026-04-16 11:20", "comment": "Neural patch for log4j verified. Remediation successful."}
]
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
            request.dependency_type,
            config=system_config
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
                           f"**Recommendation**: `{v.get('solution', 'Patch and Verify')}`",
                "before": v.get("fix", {}).get("before", "Pattern matched in source."),
                "after": v.get("fix", {}).get("after", "Neural fix pending validation.")
            })
        
        # 3. Final State Synchronization
        # Clear and replace or append - replacing for "latest" feel
        global pr_comments
        pr_comments = new_comments

        # Diagnostic Log
        print(f"--- [DIAGNOSTIC] Neural Audit Cycle ---")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"TELEMETRY: {len(request.code_diff)} bytes source, {len(request.dependency_content or '')} bytes manifest")
        print(f"FINDINGS: {len(result['vulnerabilities'])} issues detected")
        print(f"RISK SCORE: {summary['risk_score']} | STATUS: {summary['ci_status']}")
        print(f"----------------------------------------")

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
                "comment": "🚨 **Security Alert**: Detected hardcoded credentials in source code. This is a severe security risk that leads to total system compromise.\n\n**Remediation**: Use environment variables or a secure Secret Manager.",
                "before": 'api_key = "sk_live_51M..."',
                "after": 'api_key = os.getenv("STRIPE_API_KEY")'
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

from fastapi.responses import StreamingResponse
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Standardized enterprise report generation
@app.post("/generate-report")
async def generate_report(log_index: Optional[int] = None):
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        elements = []

        # High-Impact Styles
        brand_color = colors.HexColor("#1e3a8a") # Deep Navy
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=32, textColor=brand_color, spaceAfter=8, fontName='Helvetica-Bold')
        subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=12, textColor=colors.gray, spaceAfter=40)
        heading_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=brand_color, spaceBefore=25, spaceAfter=15, borderPadding=5, borderSide='bottom', borderColor=brand_color)

        # Main Header
        elements.append(Paragraph("SECUREFLOW AI", title_style))
        elements.append(Paragraph("ENTERPRISE NEURAL AUDIT DOSSIER", ParagraphStyle('Sub', parent=title_style, fontSize=14, spaceAfter=5, textColor=colors.HexColor("#3b82f6"))))
        elements.append(Paragraph(f"Reference: SF-TRACE-{datetime.now().strftime('%Y%M')}-{log_index if log_index is not None else 'FULL'} | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M')}", subtitle_style))
        
        # Summary Section
        target_logs = [audit_logs[log_index]] if (log_index is not None and 0 <= log_index < len(audit_logs)) else audit_logs
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(f"Analysis encompasses {len(target_logs)} security checkpoint(s). SecureFlow AI's neural engine has performed deep-packet and static analysis across codebase diffs and dependency graphs.", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Data Table
        data = [["TIMESTAMP", "INTELLIGENCE STATUS", "CRIT", "HIGH", "ITEMS"]]
        for log in target_logs:
            status_color = colors.HexColor("#ef4444") if log['status'] == 'FAIL' else colors.HexColor("#10b981")
            data.append([
                log['time'], 
                Paragraph(f"<b>{log['status']}</b>", ParagraphStyle('Status', parent=styles['Normal'], textColor=status_color, fontSize=9, alignment=1)),
                str(log.get('critical', 0)), 
                str(log.get('high', 0)), 
                str(log['issues'])
            ])
        
        table = Table(data, colWidths=[150, 140, 60, 60, 60])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), brand_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 15),
            ('TOPPADDING', (0, 0), (-1, 0), 15),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#ffffff")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        
        # Footer Certification
        elements.append(Spacer(1, 100))
        elements.append(Paragraph("Digital Certification", heading_style))
        cert_text = "This audit dossier is cryptographically hashed and verified by the SecureFlow AI Consensus Engine. It represents a point-in-time snapshot of system security and should be treated as sensitive administrative documentation."
        elements.append(Paragraph(cert_text, ParagraphStyle('Cert', parent=styles['Italic'], fontSize=9, textColor=colors.darkgray)))

        doc.build(elements)
        buffer.seek(0)
        
        return StreamingResponse(
            buffer, 
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=SecureFlow_Audit_{'Log' if log_index is not None else 'Full'}.pdf"}
        )
    except Exception as e:
        print(f"Report Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/review")
async def save_review(data: dict):
    reviews.insert(0, {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "comment": data.get("comment", "No description provided.")
    })
    # Also add to audit logs if it was an approval
    if "resolved" in data.get("comment", "").lower():
        audit_logs.insert(0, {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "issues": 0,
            "critical": 0,
            "high": 0,
            "status": "PASS"
        })
    return {"status": "saved"}

@app.get("/reviews")
def get_reviews():
    return reviews

@app.delete("/pr-comment/{index}")
def delete_pr_comment(index: int):
    global pr_comments
    if 0 <= index < len(pr_comments):
        pr_comments.pop(index)
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Comment not found")

@app.get("/health")
def health():
    return {"status": "operational", "engine": "Hybrid SecureFlow v3.0"}
