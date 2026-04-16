from google import genai
import os
import json
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

AI_PROMPT = """
You are a senior DevSecOps Security Researcher. 
Analyze the following vulnerability and provide a concise JSON object.
Vulnerability: {vuln_info}
Context: {context}

Output ONLY JSON matching this structure:
{{
  "explanation": "Simple language explanation",
  "root_cause": "Architectural technical cause",
  "exploit_scenario": "Step-by-step attack flow",
  "fix_steps": ["step 1", "step 2"],
  "remediation": "Technical fix recommendation"
}}
"""

class AIAnalyzer:
    def __init__(self):
        if GEMINI_API_KEY:
            self.client = genai.Client(api_key=GEMINI_API_KEY)
        else:
            self.client = None

    async def analyze(self, vuln_info: str, context: str) -> dict:
        if not self.client:
            return {
                "explanation": "AI Analysis unavailable (Missing Key).",
                "root_cause": "Detection based on static rules.",
                "exploit_scenario": "Simulated exploit path.",
                "fix_steps": ["Verify package versions", "Apply security patches"],
                "remediation": "Manual review required."
            }

        try:
            # Note: client.models.generate_content is normally synchronous in the current SDK 
            # unless using a specific async wrapper or if it's the newer async version
            response = self.client.models.generate_content(
                model="gemini-1.5-flash",
                contents=AI_PROMPT.format(vuln_info=vuln_info, context=context)
            )
            return self._parse_json(response.text)
        except Exception as e:
            print(f"AI Error: {e}")
            return {"error": str(e)}

    def _parse_json(self, text: str) -> dict:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except:
            return {}
