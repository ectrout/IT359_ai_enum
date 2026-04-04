from nmap_scan import NmapScan
from ollama_client import Ollamaclient
from service_enum import ServiceEnumerator
from nvd_lookup import NVDLookup
from msf_suggester import MSFSuggester
import os
import json

"""
main.py

xRECON - AI Assisted Penetration Testing Framework

Pipeline:
    Phase 1 — Nmap broad scan
    Phase 2 — Ollama summarizes scan
    Phase 3 — Ollama full analysis
    Phase 4 — Ollama recommends enumeration targets
    Phase 5 — User selects targets
    Phase 6 — ServiceEnumerator runs targeted enumeration
    Phase 7 — Ollama analyzes enumeration findings
    Phase 8 — NVD CVE cross-reference
    Phase 9 — Metasploit module suggestions + .rc script

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework
"""


def load_config(path="config.json") -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("[!] config.json not found. Using defaults.")
        return {
            "timeout":   60,
            "wordlist":  "/usr/share/wordlists/dirb/common.txt",
            "gobuster":  True,
            "nikto":     True,
            "fast_scan": False
        }
    except Exception as e:
        print(f"[!] Error loading config: {e}")
        return {}


def nmap_to_ai(target, client, config):
    print(f"\n[+] Starting Nmap scan on {target}")

    # ----------------------------------------------------------------
    # Phase 1: Nmap broad scan
    # Fast scan mode uses top 1000 ports — set "fast_scan": true in config
    # ----------------------------------------------------------------
    scanner = NmapScan(target, fast=config.get("fast_scan", False))
    scanner.run()

    nmap_output = scanner.get_output()

    if not nmap_output:
        print("[-] No output from Nmap. Exiting...")
        return

    print("[+] Scan complete. Sending to Ollama...\n")

    # ----------------------------------------------------------------
    # Phase 2: Ollama summarizes the scan
    # ----------------------------------------------------------------
    summary_prompt = f"""
Summarize the following Nmap scan in 5 bullet points.
Do NOT repeat text. Do NOT include recommendations.

Nmap Output:
{nmap_output}
"""
    summary = client.chat(summary_prompt)
    client.remember(f"Summary for {target}:\n{summary}")

    # ----------------------------------------------------------------
    # Phase 3: Ollama full analysis
    # ----------------------------------------------------------------
    analysis_prompt = f"""
You are a cybersecurity analysis assistant.

Analyze the following Nmap scan results and provide:
- Summary of open ports and services
- Possible vulnerabilities based on versions
- Potential attack paths
- Recommended next steps for reconnaissance
- Any misconfigurations or high risk findings

Nmap Output:
{nmap_output}
"""
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # ----------------------------------------------------------------
    # Phase 4: Ollama recommends enumeration targets
    # ----------------------------------------------------------------
    enum_prompt = f"""
Based on this analysis, return ONLY a JSON object with this exact structure:
{{
    "enumerate": [
        {{"port": 80, "service": "http", "reason": "Apache 2.4.49 detected"}},
        {{"port": 445, "service": "smb", "reason": "SMB signing disabled"}}
    ]
}}

Rules:
- port must be an integer
- service must be one of: http, https, smb, ftp, ssh, smtp
- reason must explain WHY this port needs deeper enumeration
- Return ONLY the JSON object, no extra text

Analysis:
{analysis}
"""
    enum_json_raw = client.chat(enum_prompt)

    print("\n[+] Ollama recommended enumeration targets:\n")
    print(enum_json_raw)

    try:
        clean        = enum_json_raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed       = json.loads(clean)
        enum_targets = parsed.get("enumerate", [])
    except Exception as e:
        print(f"[!] Could not parse enumeration JSON: {e}")
        return

    if not enum_targets:
        print("[!] Ollama returned no enumeration targets.")
        return

    # ----------------------------------------------------------------
    # Phase 5: User selects which ports to enumerate
    # ----------------------------------------------------------------
    print("\n[+] Enumeration targets:\n")
    for i, t in enumerate(enum_targets, start=1):
        print(f"  {i}. Port {t['port']} ({t['service']}) — {t['reason']}")

    choice = input("\nSelect targets to enumerate (e.g. 1,2 / 'all' / 'none'): ").strip().lower()

    if choice == "none":
        print("[+] No targets selected. Returning to prompt.\n")
        return

    if choice == "all":
        selected_targets = enum_targets
    else:
        try:
            indexes          = [int(x.strip()) for x in choice.split(",")]
            selected_targets = [enum_targets[i - 1] for i in indexes if 1 <= i <= len(enum_targets)]
        except Exception:
            print("[!] Invalid selection.\n")
            return

    if not selected_targets:
        print("[!] No valid targets selected.\n")
        return

    # ----------------------------------------------------------------
    # Phase 6: ServiceEnumerator runs targeted enumeration
    # ----------------------------------------------------------------
    print(f"\n[+] Running enumeration on {len(selected_targets)} target(s)...\n")

    enumerator = ServiceEnumerator(target, config)
    findings   = enumerator.enumerate(selected_targets)

    print("\n[+] Enumeration complete.\n")
    print(json.dumps(findings, indent=2))

    # ----------------------------------------------------------------
    # Phase 7: Ollama analyzes enumeration findings
    # ----------------------------------------------------------------
    findings_prompt = f"""
You are a cybersecurity analysis assistant.

The following enumeration data was collected from {target}.
Analyze the findings and provide:
- What vulnerabilities were confirmed
- Which findings are highest priority and why
- Recommended next steps

Enumeration findings:
{json.dumps(findings, indent=2)}
"""
    findings_analysis = client.chat(findings_prompt)

    print("\n[+] Ollama findings analysis:\n")
    print(findings_analysis)

    client.remember(f"Enumeration findings for {target}:\n{findings_analysis}")

    # ----------------------------------------------------------------
    # Phase 8: NVD CVE cross-reference
    # ----------------------------------------------------------------
    nvd        = NVDLookup()
    cve_list   = nvd.run(findings, client)

    if cve_list:
        print("\n[+] CVE findings (sorted by severity):\n")
        for c in cve_list:
            print(f"  [{c.get('severity', 'N/A')}] {c.get('cve_id')} — "
                  f"{c.get('software')} {c.get('version')} "
                  f"(Score: {c.get('score')})")
            print(f"      {c.get('description', '')}\n")

        nvd.save_results(cve_list, target)

    # ----------------------------------------------------------------
    # Phase 9: Metasploit module suggestions + .rc script
    # ----------------------------------------------------------------
    msf         = MSFSuggester(target)
    suggestions = msf.run(cve_list, findings, client)

    if suggestions:
        msf.save_results(suggestions)


if __name__ == "__main__":
    config = load_config()

    client = Ollamaclient(
        url     = config.get("ollama_url", "http://sushi.it.ilstu.edu:8080"),
        api_key = os.environ.get("API_KEY"),
        model   = config.get("model", "llama3.3:latest")
    )

    while True:
        target = input("\nEnter target IP (or 'exit' / 'reset'): ").strip().lower()

        if target == "exit":
            print("[+] Exiting xRECON.")
            break

        if target == "reset":
            client.reset()
            print("[+] Ollama memory reset.\n")
            continue

        if target:
            nmap_to_ai(target, client, config)
