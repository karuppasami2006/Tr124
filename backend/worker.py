from celery import Celery
import os
from .scanner import HybridScanner
from .models import SessionLocal, ScanResult
import asyncio

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "secureflow_worker",
    broker=REDIS_URL,
    backend=REDIS_URL
)

@celery_app.task(name="run_security_scan")
def run_security_scan(scan_id: str, code_diff: str, dep_content: str, dep_type: str):
    """
    Background worker task to perform heavy lifting: 
    NVD lookups + AI analysis.
    """
    scanner = HybridScanner()
    loop = asyncio.get_event_loop()
    
    # Run the async scanner in the sync Celery worker
    results = loop.run_until_complete(
        scanner.scan(code_diff, dep_content, dep_type)
    )
    
    # Save results to database (e.g. Postgres)
    db = SessionLocal()
    try:
        scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan_record:
            scan_record.status = "COMPLETED"
            scan_record.data = results
            db.commit()
    finally:
        db.close()
    
    return results
