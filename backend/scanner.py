import re
import asyncio
from typing import List, Dict, Any
from dependency_parser import parse_requirements, parse_package_json
from cve_fetcher import NVDClient
from ai_analyzer import AIAnalyzer
from risk_engine import calculate_risk

class HybridScanner:
    def __init__(self):
        self.nvd = NVDClient()
        self.ai = AIAnalyzer()

    async def scan(self, code_diff: str, dep_content: str, dep_type: str = "requirements") -> Dict[str, Any]:
        vulnerabilities = []
        
        # 1. Dependency Scan
        if dep_content:
            deps = parse_requirements(dep_content) if dep_type == "requirements" else parse_package_json(dep_content)
            for d in deps:
                vuln = await self.nvd.get_integrated_vuln(d['package'], d['version'])
                if vuln:
                    vulnerabilities.append({
                        "type": "dependency",
                        "id": f"dep-{d['package']}",
                        "file_or_package": d['package'],
                        "title": f"Vulnerable Dependency: {d['package']}",
                        "severity": vuln['severity'],
                        "confidence": 0.9,
                        "explanation": vuln['description'],
                        "fix": {"before": f"{d['package']}=={d['version']}", "after": f"{d['package']}=={vuln['safe_version']}"},
                        "fix_steps": [f"Update {d['package']} to version {vuln['safe_version']}"],
                        "cve_id": vuln['cve_id']
                    })

        # 2. Advanced AI Audit (Reasoning-based)
        ai_result = await self.ai.full_audit(code_diff)
        ai_vulns = ai_result.get("vulnerabilities", [])
        
        for v in ai_vulns:
            # Map AI fields to internal structure if needed
            v["id"] = f"ai-{v.get('type', 'vuln').lower().replace(' ', '-')}"
            vulnerabilities.append(v)

        # 3. Rule-Based Fallback (High-Confidence patterns)
        # We only add if AI missed it (simple deduplication by type/line)
        code_rules = [
            {"name": "SQL Injection", "regex": r"execute\(.*['\"].*\+.*['\"].*\)", "severity": "High", "before": "execute(\"", "after": "execute(\"%s\", (param,))"},
            {"name": "Hardcoded Secret", "regex": r"(API_KEY|TOKEN|SECRET)\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]", "severity": "High", "before": "API_KEY =", "after": "API_KEY = os.getenv('API_KEY')"},
            {"name": "Unsafe Exec", "regex": r"exec\(|eval\(", "severity": "Critical", "before": "eval(", "after": "# Unsafe eval() removed"}
        ]

        for rule in code_rules:
            match = re.search(rule['regex'], code_diff, re.IGNORECASE)
            if match:
                # Check if AI already found an issue of this type
                if not any(v.get('type') == rule['name'] for v in vulnerabilities):
                    vulnerabilities.append({
                        "type": "code",
                        "id": f"rule-{rule['name'].lower().replace(' ', '-')}",
                        "file_or_package": "source_code",
                        "title": rule['name'],
                        "severity": rule['severity'],
                        "confidence": 0.8,
                        "explanation": f"Pattern-based detection identified a potential {rule['name']}.",
                        "fix": {"before": rule['before'], "after": rule['after']},
                        "fix_steps": ["Refactor the code to use secure patterns", "Follow security best practices"]
                    })


        # 4. Global Risk Assessment
        risk = calculate_risk(vulnerabilities)

        return {
            "scan_summary": {
                "total_issues": len(vulnerabilities),
                "confidence": ai_result.get("scan_summary", {}).get("confidence", 0.7),
                "critical": risk['counts']['Critical'],
                "high": risk['counts']['High'],
                "medium": risk['counts']['Medium'],
                "low": risk['counts']['Low'],
                "ci_status": risk['status'],
                "risk_score": risk['score'],
                "decision_reason": risk['reason']
            },
            "vulnerabilities": vulnerabilities
        }
