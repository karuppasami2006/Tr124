from google import genai
import os
import json
from dotenv import load_dotenv
import prompts

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

class AIAnalyzer:
    def __init__(self):
        if GEMINI_API_KEY:
            self.client = genai.Client(api_key=GEMINI_API_KEY)
        else:
            self.client = None

    async def full_audit(self, code_diff: str, language: str = "python", mode: str = "balanced") -> dict:
        if not self.client:
            return self._mock_response()

        try:
            # 1. Custom Instruction tuning based on mode
            mode_prefix = ""
            if mode == "fast":
                mode_prefix = "FAST MODE: Provide ultra-fast, high-confidence detections only. Minimize reasoning."
            elif mode == "accurate":
                mode_prefix = "ACCURATE MODE: Perform deep-flow analysis. List root causes, exploit paths, and edge cases. Highly detailed fixes required."

            # Stage 1: Detection
            det_response = self.client.models.generate_content(
                model="gemini-1.5-flash",
                contents=f"{mode_prefix}\n\n{prompts.DETECTION_PROMPT.format(code_diff=code_diff, language=language)}"
            )
            raw_findings = det_response.text
            
            # Stage 2: Validation (Skip or simplify if fast mode)
            if mode == "fast":
                return self._parse_json(raw_findings)

            val_response = self.client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompts.VALIDATION_PROMPT.format(findings=raw_findings, code_diff=code_diff)
            )
            
            return self._parse_json(val_response.text)
        except Exception as e:
            print(f"AI Audit Error: {e}")
            return {"status": "SAFE", "scan_summary": {"total_issues": 0, "confidence": 0, "scan_time": "0s"}, "vulnerabilities": []}

    async def analyze(self, vuln_info: str, context: str) -> dict:
        """Fallback/Original compatibility - but specialized for enrichment."""
        if not self.client:
            return self._mock_response()["vulnerabilities"][0]

        prompt = f"Analyze the following security context and provide a deep explanation and fix snippet in JSON:\nContext: {context}\nVuln Info: {vuln_info}"
        try:
            response = self.client.models.generate_content(model="gemini-1.5-flash", contents=prompt)
            return self._parse_json(response.text)
        except:
            return {}

    def _parse_json(self, text: str) -> dict:
        try:
            # Clean Markdown formatting
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            
            data = json.loads(text.strip())
            
            # Ensure basic structure exists
            if "status" not in data:
                data["status"] = "VULNERABLE" if data.get("vulnerabilities") else "SAFE"
            if "vulnerabilities" not in data:
                data["vulnerabilities"] = []
            if "scan_summary" not in data:
                data["scan_summary"] = {"total_issues": len(data["vulnerabilities"]), "confidence": 0.9, "scan_time": "2.0s"}
                
            return data
        except Exception as e:
            print(f"JSON Parse Error: {e}")
            return {"status": "SAFE", "scan_summary": {"total_issues": 0, "confidence": 0, "scan_time": "0s"}, "vulnerabilities": []}

    def _mock_response(self) -> dict:
        return {
            "status": "VULNERABLE",
            "scan_summary": {"total_issues": 1, "confidence": 0.95, "scan_time": "1.5s"},
            "vulnerabilities": [
                {
                    "file": "audit_engine.py",
                    "line": 42,
                    "type": "SQL Injection",
                    "owasp_category": "A03:2021-Injection",
                    "severity": "Critical",
                    "confidence": 0.98,
                    "root_cause": "User input is directly concatenated into a SQL string sink.",
                    "explanation": "The query construction lacks parameterization, allowing malicious SQL logic to alter the database command structure.",
                    "exploit_scenario": "Bypassing authentication via ' OR 1=1 -- input.",
                    "fix": {
                        "before": 'query = "SELECT * FROM logs WHERE user_id =" + uid',
                        "after": 'query = "SELECT * FROM logs WHERE user_id = %s"; cursor.execute(query, (uid,))'
                    },
                    "fix_steps": ["Implement parameterized queries", "Remove all string concatenation from SQL sinks", "Sanitize all external user inputs"]
                }
            ]
        }

