#!/usr/bin/env python3

import os
import sys
import json
import subprocess

from nmap_parser import NmapXMLParser
from nvd_lookup import NVDLookupStructured
from prompts import build_analysis_prompt, build_test_plan_prompt
from ollama_client import Ollamaclient
from service_enum import ServiceEnumerator
from msf_suggester import MSFSuggester      # replaces ModuleIntel — searches msfconsole directly
from poc_intel import PoCIntel
from update_module_metadata import main as update_modules


def run_nmap_xml(target: str, xml_path: str = "scan.xml") -> bool:
    """
    Runs Nmap with version detection and saves structured XML output.
    XML gives us clean port/service/version data for enumeration and CVE lookup.
    """
    cmd = ["nmap", "-sV", "-oX", xml_path, target]
    print(f"[+] Running Nmap: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] Nmap not found.")
        return False

    if result.returncode != 0:
        print("[!] Nmap scan failed:")
        print(result.stderr)
        return False

    print(f"[+] Nmap scan completed. XML saved to {xml_path}")
    return True


def nmap_to_ai_structured(target: str, client: Ollamaclient):
    xml_path    = "scan.xml"
    safe_target = target.replace(".", "_")

    # ----------------------------------------------------------------
    # Phase 1: Nmap scan → structured XML parse
    # ----------------------------------------------------------------
    if not run_nmap_xml(target, xml_path):
        return

    parser     = NmapXMLParser(xml_path)
    scan_model = parser.parse()
    host_count = len(scan_model.get("hosts", []))
    print(f"[+] Parsed scan model: {host_count} host(s) detected")

    # ----------------------------------------------------------------
    # Phase 2: Ollama initial offensive analysis of nmap results
    # No defensive recommendations — pure attack surface mapping
    # ----------------------------------------------------------------
    analysis_prompt = build_analysis_prompt(scan_model, [])
    print("\n[~] Sending scan to Ollama for analysis...")
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # ----------------------------------------------------------------
    # Phase 3: ServiceEnumerator — deep per-port enumeration
    #
    # Runs BEFORE NVD lookup intentionally — enumeration output
    # gives us more accurate version strings than nmap alone,
    # which leads to better CVE matches downstream.
    #
    # Per-port tool chain:
    #   http/https → curl headers + gobuster + nikto
    #   smb        → enum4linux + smbclient null session + nmap smb-vuln*
    #   ftp        → nmap ftp scripts + anonymous login attempt
    #   ssh        → nmap ssh scripts + banner grab
    #   smtp       → nmap smtp scripts + VRFY user probe
    #   unknown    → nmap -sV fallback
    # ----------------------------------------------------------------
    print("\n[+] Building enumeration target list from scan...\n")

    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path) as f:
            config = json.load(f)
    except Exception:
        config = {
            "timeout":  60,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "gobuster": True,
            "nikto":    True
        }

    service_map = {
        "ftp":          "ftp",
        "proftpd":      "ftp",
        "ssh":          "ssh",
        "openssh":      "ssh",
        "http":         "http",
        "https":        "https",
        "ssl/http":     "https",
        "microsoft-ds": "smb",
        "netbios-ssn":  "smb",
        "samba":        "smb",
        "smtp":         "smtp",
        "mysql":        "http",
        "jetty":        "http",
        "apache":       "http",
        "nginx":        "http",
        "cups":         "http",
    }

    port_list = []
    for host in scan_model.get("hosts", []):
        for svc in host.get("services", []):
            product     = svc.get("product") or ""
            version     = svc.get("version") or ""
            service_raw = product.lower().split()[0] if product else ""
            service     = service_map.get(service_raw, service_raw)

            port_list.append({
                "port":    svc.get("port"),
                "service": service,
                "reason":  f"{product} {version} detected".strip()
            })

    if not port_list:
        print("[!] No open ports found to enumerate.")
        return

    print("[+] Ports queued for enumeration:\n")
    for i, p in enumerate(port_list, start=1):
        print(f"  {i}. Port {p['port']} ({p['service']}) — {p['reason']}")

    choice = input("\nSelect ports (e.g. 1,2 / 'all' / 'none'): ").strip().lower()

    if choice == "none":
        print("[+] Skipping enumeration.")
        findings = {"target": target, "findings": []}
    elif choice == "all":
        enumerator = ServiceEnumerator(target, config)
        findings   = enumerator.enumerate(port_list)
    else:
        try:
            indexes    = [int(x.strip()) for x in choice.split(",")]
            selected   = [port_list[i - 1] for i in indexes if 1 <= i <= len(port_list)]
            enumerator = ServiceEnumerator(target, config)
            findings   = enumerator.enumerate(selected)
        except Exception:
            print("[!] Invalid selection — skipping enumeration.")
            findings = {"target": target, "findings": []}

    # Save full enumeration output to file — keeps console readable
    enum_filename = f"{safe_target}_enumeration.json"
    with open(enum_filename, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] Full enumeration saved to {enum_filename}")
    print(f"    View with: cat {enum_filename}\n")

    # One-line console summary per port
    print("[+] Enumeration summary:")
    for f in findings.get("findings", []):
        status = "OK" if not f.get("error") else f"ERR: {f.get('error')}"
        print(f"    Port {f.get('port')} ({f.get('service')}) — {f.get('tool')} — {status}")

    # ----------------------------------------------------------------
    # Phase 4: Ollama offensive attack path analysis
    # Reads what the tools actually found and tells you what to hit first
    # No defensive recommendations — that goes in the report at the end
    # ----------------------------------------------------------------
    print("\n[+] Asking Ollama for offensive attack paths...")

    # Build summary outside the f-string to avoid dict/set confusion
    findings_summary = json.dumps([
        {
            "port":    f.get("port"),
            "service": f.get("service"),
            "output":  (f.get("output") or "")[:800]
        }
        for f in findings.get("findings", [])
    ], indent=2)

    findings_prompt = f"""
    You are an offensive penetration tester.
    Do NOT suggest fixes or defensive recommendations.

    Analyze these enumeration findings from {target} and provide:
    - Confirmed vulnerabilities and what makes them exploitable
    - Specific attack paths ranked by likelihood of success
    - Credentials, misconfigs, or exposed services worth targeting
    - What to try first and why

    Enumeration findings:
    {findings_summary}
    """
    enum_analysis = client.chat(findings_prompt)

    print("\n[+] Attack path analysis:\n")
    print(enum_analysis)

    # Store in memory for defensive report later
    client.remember(f"Attack paths for {target}:\n{enum_analysis}")

    # ----------------------------------------------------------------
    # Phase 5: NVD CVE lookup
    # Runs after enumeration so we have the most complete version info
    # ----------------------------------------------------------------
    nvd           = NVDLookupStructured(results_per_page=5)
    software_list = nvd.build_software_list(scan_model)
    print(f"\n[+] Software list built with {len(software_list)} entries")

    cve_list = nvd.lookup_cves(software_list)
    print(f"[+] NVD lookup returned {len(cve_list)} CVE(s)")

    if cve_list:
        print("\n[+] CVE findings (top 5 by severity):\n")
        sorted_cves = sorted(cve_list, key=lambda x: x.get("cve_id", ""), reverse=True)
        for c in sorted_cves[:5]:
            print(f"  {c.get('cve_id')} — {c.get('product')} {c.get('version')} (port {c.get('port')})")

        cve_filename = f"{safe_target}_cves.json"
        with open(cve_filename, "w") as f:
            json.dump(cve_list, f, indent=2)
        print(f"\n[+] All CVEs saved to {cve_filename}")

    # ----------------------------------------------------------------
    # Phase 6: AI test plan with full context
    # ----------------------------------------------------------------
    test_plan_prompt = build_test_plan_prompt(scan_model, cve_list, target)
    print("\n[~] Requesting test plan from AI...")
    test_plan_raw = client.chat(test_plan_prompt)

    try:
        clean     = test_plan_raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        test_plan = json.loads(clean)
        tests     = test_plan.get("tests", [])
    except Exception as e:
        print(f"[!] Could not parse test plan JSON: {e}")
        tests = []

    print("\n[+] Suggested next steps:\n")
    if not tests:
        print("[!] AI did not suggest any tests.")
    else:
        for i, t in enumerate(tests, start=1):
            print(f"  {i}. {t.get('name')} (port {t.get('port')}) — {t.get('description')}")

    # ----------------------------------------------------------------
    # Phase 7: Metasploit module suggestions
    # Searches msfconsole directly by CVE ID — no hallucination
    # Falls back to software name search if CVE returns nothing
    # Generates ready-to-run .rc script
    # ----------------------------------------------------------------
    if cve_list:
        msf         = MSFSuggester(target)
        suggestions = msf.run(cve_list, findings, client)
        if suggestions:
            msf.save_results(suggestions)

    # ----------------------------------------------------------------
    # Phase 8: GitHub PoC intelligence
    # Pulls directly from cve_list — was broken before because it
    # was reading from seen_cves which was populated by ModuleIntel
    # (which found nothing). Now reads CVEs directly from NVD results.
    # ----------------------------------------------------------------
    poc_intel = PoCIntel(github_token=os.environ.get("GITHUB_TOKEN"))
    print("\n[+] GitHub PoC intelligence:\n")

    for cve_entry in cve_list[:5]:
        cve_id = cve_entry.get("cve_id")
        if not cve_id:
            continue
        pocs = poc_intel.search_pocs_for_cve(cve_id)
        if not pocs:
            continue
        print(f"  CVE: {cve_id}")
        for p in pocs:
            print(f"    Repo: {p['name']} ({p['html_url']})")
            print(f"    Stars: {p['stargazers_count']} — {p['description']}")

    # ----------------------------------------------------------------
    # Phase 9: Defensive report saved to file only
    # Only place in the pipeline where remediation appears
    # ----------------------------------------------------------------
    print("\n[+] Generating defensive report (saved to file only)...")

    defensive_prompt = f"""
You are writing a professional penetration test report.

Target: {target}

Based on all findings provide:
- Executive summary of vulnerabilities found
- Risk ratings (Critical / High / Medium / Low)
- Specific remediation steps for each vulnerability
- Patch recommendations with version numbers
- Configuration hardening suggestions

Write as a formal report section, not bullet points.
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
{enum_analysis}

CVE FINDINGS
------------
{json.dumps(cve_list, indent=2) if cve_list else "No CVEs found."}

DEFENSIVE RECOMMENDATIONS
-------------------------
{defensive_report}
"""
    report_filename = f"{safe_target}_report.txt"
    with open(report_filename, "w") as f:
        f.write(report_content)
    print(f"[+] Report saved to {report_filename}")
    print(f"    View with: cat {report_filename}")

    # Trim history after full run to prevent context window bloat
    client.trim_history(keep_pairs=2)

    print(f"\n[+] xRECON complete. Files generated:")
    print(f"    {safe_target}_nmap.txt             — raw nmap output (if saved)")
    print(f"    {safe_target}_enumeration.json     — full enumeration data")
    print(f"    {safe_target}_cves.json            — CVE findings")
    print(f"    {safe_target}_msf_suggestions.json — Metasploit modules")
    print(f"    {safe_target}_modules.rc           — ready-to-run msfconsole script")
    print(f"    {safe_target}_report.txt           — full pentest report\n")


def main():
    if "--update-modules" in sys.argv:
        update_modules()
        return

    client = Ollamaclient(
        url     = os.environ.get("OLLAMA_URL", "http://sushi.it.ilstu.edu:8080"),
        api_key = os.environ.get("API_KEY"),
        model   = os.environ.get("OLLAMA_MODEL", "llama3.3:latest"),
    )

    print("[+] IT359 AI Enum — Structured Mode")
    print("    Flags: --update-modules")
    print("    Commands: 'reset' to reset AI context, 'exit' to quit.\n")

    while True:
        target = input("Enter target IP/host: ").strip()
        if not target:
            continue
        if target.lower() == "exit":
            print("[*] Exiting.")
            break
        if target.lower() == "reset":
            print("[*] Resetting AI client context.")
            client.reset()
            continue
        nmap_to_ai_structured(target, client)


if __name__ == "__main__":
    main()
