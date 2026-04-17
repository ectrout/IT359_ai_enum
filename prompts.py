def build_analysis_prompt(scan_model, cve_list):
    return f"""
You are a cybersecurity analyst.

You are given:
1) Structured scan data (ports, services, products, versions, scripts)
2) A list of CVEs matched to some services

Your tasks:
- Summarize the attack surface
- Highlight high-risk services and ports
- Explain likely attack paths
- Note misconfigurations or weak services
- Suggest high-level next steps

Scan data (JSON):
{scan_model}

Matched CVEs (JSON):
{cve_list}

Respond in clear sections with bullet points.
"""

def build_test_plan_prompt(scan_model, cve_list, target):
    return f"""
You are a penetration tester.

Given:
- Structured scan data (ports, services, products, versions)
- Matched CVEs

Return ONLY a JSON object with this shape:

{{
  "tests": [
    {{
      "name": "short test name",
      "description": "what to check or attempt",
      "target": "{target}",
      "port": 1234
    }}
  ]
}}

Rules:
- No commands, no tools, no code.
- High-level test descriptions only.
- Include tests even for services without known versions.
- Prioritize likely exploitable or high-impact services.

Scan data:
{scan_model}

CVEs:
{cve_list}
"""
