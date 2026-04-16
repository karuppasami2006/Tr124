import json
import os
from typing import Dict, Optional, List

# Load local database
DB_PATH = os.path.join(os.path.dirname(__file__), "cve_database.json")

def load_local_db() -> List[Dict]:
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading local CVE DB: {e}")
        return []

def get_cve_from_local(cve_id: str) -> Optional[Dict]:
    db = load_local_db()
    for item in db:
        if item["cve_id"].upper() == cve_id.upper():
            return item
    return None

def get_top_cves() -> List[Dict]:
    return load_local_db()

async def enrich_cve_data(cve_data: Dict, ai_analyzer=None) -> Dict:
    """Enrich CVE data with AI summaries if available."""
    if not ai_analyzer:
        return cve_data
        
    try:
        prompt = f"Summarize this CVE for a developer. Keep it actionable. CVE: {cve_data['cve_id']} - {cve_data['name']}"
        context = cve_data['description']
        ai_summary = await ai_analyzer.analyze(prompt, context)
        
        cve_data['ai_insights'] = ai_summary.get('explanation', "AI insights pending.")
        return cve_data
    except:
        return cve_data
