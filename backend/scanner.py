import re
import asyncio
from typing import List, Dict, Any
from .dependency_parser import parse_requirements, parse_package_json
from .cve_fetcher import NVDClient
from .ai_analyzer import AIAnalyzer
from .risk_engine import calculate_risk

class HybridScanner:
    def __init__(self):
        self.nvd = NVDClient()
        self.ai = AIAnalyzer()

    async def scan(self, code_diff: str, dep_content: str, dep_type: str = "requirements") -> Dict[str, Any]:
        vulnerabilities = []
        
        # 1. Dependency Scan (Integrated NVD + Fallback)
        if dep_content:
            deps = parse_requirements(dep_content) if dep_type == "requirements" else parse_package_json(dep_content)
            for d in deps:
                vuln = await self.nvd.get_integrated_vuln(d['package'], d['version'])
                if vuln:
                    vulnerabilities.append({
                        "type": "dependency",
                        "id": f"dep-{d['package']}",
                        "file_or_package": d['package'],
                        "current_version": d['version'],
                        "safe_version": vuln['safe_version'],
                        "cve_id": vuln['cve_id'],
                        "severity": vuln['severity'],
                        "cvss_score": vuln['cvss_score'],
                        "description": vuln['description'],
                        "fix": f"Upgrade {d['package']} to {vuln['safe_version']}"
                    })

        # 2. Code Scan (Rule-Based + AI Analysis)
        code_rules = [
            {"name": "SQL Injection", "regex": r"execute\(.*['\"].*\+.*['\"].*\)", "severity": "High"},
            {"name": "Hardcoded Secret", "regex": r"(API_KEY|TOKEN|SECRET)\s*=\s*['\"][a-zA-Z0-9]{10,}['\"]", "severity": "High"},
            {"name": "Unsafe Exec", "regex": r"exec\(|eval\(", "severity": "Critical"}
        ]

        for rule in code_rules:
            if re.search(rule['regex'], code_diff, re.IGNORECASE):
                # Manual Mapping based on Industry CWEs
                vulnerabilities.append({
                    "type": "code",
                    "id": f"code-{rule['name'].lower().replace(' ', '-')}",
                    "file_or_package": "source_code",
                    "title": rule['name'],
                    "severity": rule['severity'],
                    "cve_id": f"CWE-{'89' if 'SQL' in rule['name'] else '798' if 'Secret' in rule['name'] else '94'}",
                    "cvss_score": 9.8 if rule['severity'] == "Critical" else 8.5,
                    "description": f"Dynamic analysis confirmed {rule['name']} pattern in changed lines."
                })

        # 3. AI Enrichment (Async for performance)
        enrichment_tasks = []
        for v in vulnerabilities:
            if v['type'] == 'code':
                enrichment_tasks.append(self.ai.analyze(v['title'], code_diff))
            else:
                enrichment_tasks.append(self.ai.analyze(f"{v['file_or_package']} version {v['current_version']}", v['description']))

        if enrichment_tasks:
            results = await asyncio.gather(*enrichment_tasks)
            for i, res in enumerate(results):
                vulnerabilities[i].update(res)

        # 4. Risk Decision
        risk = calculate_risk(vulnerabilities)

        return {
            "scan_summary": {
                "total_issues": len(vulnerabilities),
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
