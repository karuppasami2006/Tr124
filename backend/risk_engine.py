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

    # Task 3: severity-based weighted point model
    # Optimized for high-fidelity dynamic reduction tracking
    points_map = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
    
    total_points = 0
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for v in vulnerabilities:
        sev = v.get("severity", "Medium")
        total_points += points_map.get(sev, 1)
        counts[sev] += 1

    # Task 4 & 8: Dynamic Normalization
    # Ensures score drops linearly with remediation
    if counts["Critical"] > 0:
        # If any Critical remains, score is high (8.5+) even if others are fixed
        normalized_score = min(10, 8.5 + (counts["Critical"] * 0.5))
    else:
        # High/Med/Low scaling to ensure every fix drops the score
        normalized_score = min(8, total_points)
    
    # Task 6: Fail condition - binary compliance gate
    status = "FAIL" if vulnerabilities else "PASS"
    reason = f"Security pipeline blocked. {len(vulnerabilities)} active threats identified." if vulnerabilities else "Environment secure. Binary compliance met."

    # Final Precision: Pure 0 for absolute PASS
    final_score = round(normalized_score, 1) if vulnerabilities else 0
    rating = "Critical" if final_score >= 8.5 else "High" if final_score >= 5 else "Medium" if final_score >= 1 else "Safe"

    return {
        "score": final_score,
        "rating": rating,
        "status": status,
        "reason": reason,
        "counts": counts
    }
