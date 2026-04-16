from typing import List, Dict

def calculate_risk(vulnerabilities: List[Dict]) -> Dict:
    if not vulnerabilities:
        return {
            "score": 0,
            "rating": "Low",
            "status": "PASS",
            "reason": "Secure baseline achieved. No active threats found."
        }

    severity_map = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}
    
    total_score = 0
    max_severity = "Low"
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for v in vulnerabilities:
        sev = v.get("severity", "Medium")
        total_score += severity_map.get(sev, 5)
        counts[sev] += 1
        
        # Track highest severity
        if severity_map.get(sev, 0) > severity_map.get(max_severity, 0):
            max_severity = sev

    avg_score = min(total_score / len(vulnerabilities), 10)
    
    # Decision Logic
    if counts["Critical"] > 0 or counts["High"] > 0:
        status = "FAIL"
        reason = f"Pipeline blocked by {counts['Critical']} Critical and {counts['High']} High findings."
    elif counts["Medium"] > 0:
        status = "WARNING"
        reason = "Potential risk detected. Manual approval recommended."
    else:
        status = "PASS"
        reason = "Minor issues detected, within tolerance limits."

    return {
        "score": round(avg_score, 1),
        "rating": max_severity,
        "status": status,
        "reason": reason,
        "counts": counts
    }
