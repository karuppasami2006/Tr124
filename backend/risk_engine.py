from typing import List, Dict

def calculate_risk(vulnerabilities: List[Dict]) -> Dict:
    # Task 1 & 5: Absolute zero reset for PASS state
    if not vulnerabilities:
        return {
            "score": 0,
            "rating": "Safe",
            "status": "PASS",
            "reason": "Security baseline verified. environment is compliant.",
            "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        }

    # Task 3: severity-based point model (Exact match to requirements)
    points_map = {"Critical": 10, "High": 5, "Medium": 3, "Low": 1}
    
    total_points = 0
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # Task 8: Iterate only current vulnerabilities (no double counting)
    for v in vulnerabilities:
        sev = v.get("severity", "Medium")
        total_points += points_map.get(sev, 1)
        counts[sev] += 1

    # Task 4: Intelligence-weighted normalization
    # If any Critical issue remains, floor is 10.
    # Otherwise, linear sum up to 10.
    if counts["Critical"] > 0:
        normalized_score = 10
    else:
        normalized_score = min(10, total_points)
    
    # Task 6: Fail condition - binary compliance gate
    status = "FAIL" if vulnerabilities else "PASS"
    reason = f"Security pipeline blocked. {len(vulnerabilities)} active threats identified." if vulnerabilities else "Environment secure. Binary compliance met."

    return {
        "score": normalized_score,
        "rating": "Critical" if normalized_score >= 10 else "High" if normalized_score >= 5 else "Medium" if normalized_score >= 1 else "Safe",
        "status": status,
        "reason": reason,
        "counts": counts
    }
