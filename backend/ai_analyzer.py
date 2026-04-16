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

    async def full_audit(self, code_diff: str, language: str = "python") -> dict:
        """
        Performs a two-stage security audit: 1. Detection, 2. Validation.
        Returns a refined list of high-confidence vulnerabilities.
        """
        if not self.client:
            return self._mock_response()

        try:
            # Stage 1: Detection
            det_response = self.client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompts.DETECTION_PROMPT.format(code_diff=code_diff, language=language)
            )
            raw_findings = det_response.text
            
            # Stage 2: Validation
            val_response = self.client.models.generate_content(
                model="gemini-1.5-flash",
                contents=prompts.VALIDATION_PROMPT.format(findings=raw_findings, code_diff=code_diff)
            )
            
            return self._parse_json(val_response.text)
        except Exception as e:
            print(f"AI Audit Error: {e}")
            return {"error": str(e), "vulnerabilities": []}

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
            if "vulnerabilities" not in data:
                data["vulnerabilities"] = []
            if "scan_summary" not in data:
                data["scan_summary"] = {"total_issues": len(data["vulnerabilities"]), "confidence": 0.5}
                
            return data
        except Exception as e:
            print(f"JSON Parse Error: {e}")
            return {"scan_summary": {"total_issues": 0, "confidence": 0}, "vulnerabilities": []}

    def _mock_response(self) -> dict:
        return {
            "scan_summary": {"total_issues": 1, "confidence": 0.9, "ci_status": "FAIL"},
            "vulnerabilities": [
                {
                    "id": "ai-sql-injection-mock",
                    "type": "SQL Injection",
                    "category": "A03:2021-Injection",
                    "severity": "Critical",
                    "confidence": 0.95,
                    "explanation": "User input is directly concatenated into a SQL string without sanitization or parameterization.",
                    "root_cause": "String concatenation in database query sink.",
                    "exploit": "Attacker can bypass login by providing ' OR '1'='1 as input.",
                    "fix": {
                        "before": "db.execute(\"SELECT * FROM entries WHERE id = \" + user_id)",
                        "after": "db.execute(\"SELECT * FROM entries WHERE id = %s\", (user_id,))"
                    },
                    "fix_steps": ["Switch to parameterized queries", "Use database-specific placeholders", "Validate input type before query"]
                }
            ]
        }

