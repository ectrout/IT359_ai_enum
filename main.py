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
    Phase 2 — Ollama analysis (summary + attack surface combined)
    Phase 3 — Ollama recommends enumeration targets
    Phase 4 — User selects targets
    Phase 5 — ServiceEnumerator runs targeted enumeration (saved to file)
    Phase 6 — Ollama analyzes enumeration findings (offensive focus)
    Phase 7 — NVD CVE cross-reference (saved to file)
    Phase 8 — Metasploit module suggestions + .rc script
    Phase 9 — Defensive recommendations (saved to report file)

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
            "fast_scan": True
        }
    except Exception as e:
        print(f"[!] Error loading config: {e}")
        return {}


def save_to_file(filename: str, content: str):
    """Saves any string content to a file and tells the user where it is."""
    try:
        with open(filename, "w") as f:
            f.write(content)
        print(f"[+] Saved to {filename}")
    except Exception as e:
        print(f"[!] Could not save {filename}: {e}")


def nmap_to_ai(target, client, config):
    safe_target = target.replace(".", "_")

    print(f"\n[+] Starting Nmap scan on {target}")
    print(f"    Fast scan: {config.get('fast_scan', False)}")

    # ----------------------------------------------------------------
    # Phase 1: Nmap scan
    # ----------------------------------------------------------------
    scanner = NmapScan(target, fast=config.get("fast_scan", False))
    scanner.run()

    nmap_output = scanner.get_output()

    if not nmap_output:
        # Trim history at end of each run to prevent context window bloat
        client.trim_history(keep_pairs=2)
        print("[-] No output from Nmap. Exiting...")
        return

    # Save raw nmap output immediately
    save_to_file(f"{safe_target}_nmap.txt", nmap_output)
    print("[+] Scan complete.\n")

    # ----------------------------------------------------------------
    # Phase 2: Combined summary + attack surface analysis
    # Merged phases 2+3 to reduce Ollama memory usage
    # Offensive focus only — no defensive recommendations yet
    # ----------------------------------------------------------------
    analysis_prompt = f"""
You are an offensive security analyst conducting an authorized penetration test.

Analyze the following Nmap scan results. Be concise and offensive-focused.
Do NOT include defensive recommendations or remediation advice.

Provide:
1. Open ports and detected service versions (one line each)
2. Attack surface — what looks exploitable and why
3. Likely OS and technology stack
4. Top 3 highest-value targets ranked by exploitability

Nmap Output:
{nmap_output}
"""
    print("[+] Sending scan to Ollama for analysis...")
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # Store compact version in memory
    client.remember(f"Scan analysis for {target}:\n{analysis}")

    # ----------------------------------------------------------------
    # Phase 3: Ollama recommends enumeration targets
    # ----------------------------------------------------------------
    enum_prompt = f"""
Based on the analysis above, return ONLY a JSON object:
{{
    "enumerate": [
        {{"port": 80, "service": "http", "reason": "Apache 2.4.7 outdated, phpmyadmin exposed"}},
        {{"port": 445, "service": "smb", "reason": "Samba null session allowed"}}
    ]
}}

Rules:
- Analyze all open ports and suggest them for enumeration whenever possible based off of service version
- port must be an integer
- service must be one of: http, https, smb, ftp, ssh, smtp
- reason is ONE sentence — the specific exploitable finding
- Only include ports worth deep enumeration
- Return ONLY the JSON object, no extra text
"""
    enum_json_raw = client.chat(enum_prompt)

    try:
        clean        = enum_json_raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed       = json.loads(clean)
        enum_targets = parsed.get("enumerate", [])
    except Exception as e:
        print(f"[!] Could not parse enumeration JSON: {e}")
        print(f"    Raw: {enum_json_raw[:200]}")
        return

    if not enum_targets:
        print("[!] Ollama returned no enumeration targets.")
        return

    # ----------------------------------------------------------------
    # Phase 4: User selects which ports to enumerate
    # ----------------------------------------------------------------
    print("\n[+] Enumeration targets:\n")
    for i, t in enumerate(enum_targets, start=1):
        print(f"  {i}. Port {t['port']} ({t['service']}) — {t['reason']}")

    choice = input("\nSelect targets (e.g. 1,2 / 'all' / 'none'): ").strip().lower()

    if choice == "none":
        print("[+] No targets selected.\n")
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
    # Phase 5: ServiceEnumerator — output saved to file, not flooded to console
    # ----------------------------------------------------------------
    print(f"\n[+] Running enumeration on {len(selected_targets)} target(s)...")
    print("    This may take a few minutes. Output will be saved to file.\n")

    enumerator = ServiceEnumerator(target, config)
    findings   = enumerator.enumerate(selected_targets)

    # Save full enumeration output to file
    enum_filename = f"{safe_target}_enumeration.json"
    save_to_file(enum_filename, json.dumps(findings, indent=2))
    print(f"[+] Full enumeration output saved to {enum_filename}")
    print(f"    View with: cat {enum_filename}\n")

    # Print a short summary to console instead of the full dump
    print("[+] Enumeration summary:")
    for f in findings.get("findings", []):
        status = "OK" if not f.get("error") else f"ERR: {f.get('error')}"
        print(f"    Port {f.get('port')} ({f.get('service')}) — {f.get('tool')} — {status}")

    # ----------------------------------------------------------------
    # Phase 6: Ollama offensive analysis of findings
    # No defensive advice here — pure attack path focus
    # ----------------------------------------------------------------
    findings_prompt = f"""
You are an offensive penetration tester.
Do NOT suggest fixes or defensive recommendations.

Analyze these enumeration findings from {target} and provide:
- Confirmed vulnerabilities and what makes them exploitable
- Specific attack paths ranked by likelihood of success
- Credentials, misconfigs, or exposed services worth targeting
- What to try first and why

Enumeration findings (summarized):
{json.dumps([{
    "port": f.get("port"),
    "service": f.get("service"),
    "output": (f.get("output") or "")[:800]
} for f in findings.get("findings", [])], indent=2)}
"""
    print("\n[+] Asking Ollama for offensive attack paths...")
    findings_analysis = client.chat(findings_prompt)

    print("\n[+] Attack path analysis:\n")
    print(findings_analysis)

    client.remember(f"Attack paths for {target}:\n{findings_analysis}")

    # ----------------------------------------------------------------
    # Phase 7: NVD CVE cross-reference — saved to file
    # ----------------------------------------------------------------
    nvd      = NVDLookup()
    cve_list = nvd.run(findings, client)

    if cve_list:
        print(f"\n[+] CVE findings ({len(cve_list)} total, sorted by severity):\n")
        for c in cve_list[:5]:   # show top 5 in console, rest in file
            print(f"  [{c.get('severity', 'N/A')}] {c.get('cve_id')} — "
                  f"{c.get('software')} {c.get('version')} "
                  f"(Score: {c.get('score')})")
        if len(cve_list) > 5:
            print(f"  ... and {len(cve_list) - 5} more — see {safe_target}_cves.json")
        nvd.save_results(cve_list, target)

    # ----------------------------------------------------------------
    # Phase 8: Metasploit module suggestions + .rc script
    # ----------------------------------------------------------------
    msf         = MSFSuggester(target)
    suggestions = msf.run(cve_list, findings, client)

    if suggestions:
        msf.save_results(suggestions)

    # ----------------------------------------------------------------
    # Phase 9: Defensive report — saved to file, not printed to console
    # This is the ONLY place defensive recommendations appear
    # ----------------------------------------------------------------
    print("\n[+] Generating defensive report (saved to file only)...")

    defensive_prompt = f"""
You are now writing a professional penetration test report section.

Target: {target}

Based on all findings from this engagement, provide:
- Executive summary of vulnerabilities found
- Risk ratings for each finding (Critical / High / Medium / Low)
- Specific remediation steps for each vulnerability
- Patch recommendations with version numbers where applicable
- Configuration hardening suggestions

Write this as a formal report section, not a bullet list.
"""
    defensive_report = client.chat(defensive_prompt)

    report_content = f"""xRECON Penetration Test Report
Target: {target}
================================

NMAP ANALYSIS
-------------
{analysis}

ATTACK PATH ANALYSIS
--------------------
{findings_analysis}

CVE FINDINGS
------------
{json.dumps(cve_list, indent=2) if cve_list else "No CVEs found."}

DEFENSIVE RECOMMENDATIONS
-------------------------
{defensive_report}
"""
    report_filename = f"{safe_target}_report.txt"
    save_to_file(report_filename, report_content)
    print(f"[+] Full report saved to {report_filename}")
    print(f"    View with: cat {report_filename}\n")

    print("\n[+] xRECON complete. Files generated:")
    print(f"    {safe_target}_nmap.txt          — raw nmap output")
    print(f"    {safe_target}_enumeration.json  — full enumeration data")
    print(f"    {safe_target}_cves.json         — CVE findings")
    print(f"    {safe_target}_msf_suggestions.json — Metasploit modules")
    print(f"    {safe_target}_modules.rc        — ready to run in msfconsole")
    print(f"    {safe_target}_report.txt        — full pentest report\n")


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
