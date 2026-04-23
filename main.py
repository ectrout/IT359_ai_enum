#!/usr/bin/env python3

import os
import sys
import json
import subprocess

from nmap_parser import NmapXMLParser
from nvd_lookup import NVDLookupStructured
from prompts import build_analysis_prompt, build_test_plan_prompt
from ollama_client import Ollamaclient
from service_enum import ServiceEnumerator    # was never imported before
from module_intel import ModuleIntel
from poc_intel import PoCIntel
from update_module_metadata import main as update_modules


def run_nmap_xml(target: str, xml_path: str = "scan.xml") -> bool:
    """
    Runs Nmap with version detection and saves output as XML.
    XML gives us structured port/service/version data that
    ServiceEnumerator and NVDLookup can both use cleanly.
    """
    cmd = ["nmap", "-sV", "-oX", xml_path, target]
    print(f"[+] Running Nmap: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] Nmap not found. Install it or add it to PATH.")
        return False

    if result.returncode != 0:
        print("[!] Nmap scan failed:")
        print(result.stderr)
        return False

    print(f"[+] Nmap scan completed. XML saved to {xml_path}")
    return True


def nmap_to_ai_structured(target: str, client: Ollamaclient):
    xml_path = "scan.xml"

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
    # Phase 2: Initial Ollama analysis of nmap results
    # Offensive focus only — gives us context before enumeration
    # ----------------------------------------------------------------
    analysis_prompt = build_analysis_prompt(scan_model, [])
    print("\n[~] Sending analysis prompt to AI...")
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # ----------------------------------------------------------------
    # Phase 3: ServiceEnumerator — deep per-port enumeration
    # This is the core of the tool. Runs gobuster, nikto, enum4linux,
    # smbclient, SSH banner grabbing, FTP anonymous login, SMTP VRFY
    # against every open port nmap found.
    #
    # This runs BEFORE NVD lookup because we need the enumeration
    # output to find accurate software versions — nmap alone often
    # misses them or returns incomplete strings.
    # ----------------------------------------------------------------
    print("\n[+] Running service enumeration...\n")

    # Load config for ServiceEnumerator (wordlist, timeouts, tool flags)
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

    # Build the port list from the parsed scan model
    # ServiceEnumerator expects: [{port, service, reason}, ...]
    port_list = []
    for host in scan_model.get("hosts", []):
        for svc in host.get("services", []):
            product = svc.get("product") or ""
            version = svc.get("version") or ""

            # Normalize service name to match ServiceEnumerator handlers
            # e.g. "Apache httpd" → "http", "Samba smbd" → "smb"
            service_map = {
                "ftp":          "ftp",
                "ssh":          "ssh",
                "http":         "http",
                "https":        "https",
                "ssl/http":     "https",
                "microsoft-ds": "smb",
                "netbios-ssn":  "smb",
                "samba":        "smb",
                "smtp":         "smtp",
                "mysql":        "http",   # fallback — no mysql handler yet
                "jetty":        "http",
                "apache":       "http",
                "nginx":        "http",
            }

            # Use first word of product name as service key
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

    # Show operator what will be enumerated
    print("[+] Ports queued for enumeration:\n")
    for i, p in enumerate(port_list, start=1):
        print(f"  {i}. Port {p['port']} ({p['service']}) — {p['reason']}")

    choice = input("\nSelect ports to enumerate (e.g. 1,2 / 'all' / 'none'): ").strip().lower()

    if choice == "none":
        print("[+] Skipping enumeration.")
        findings = {"target": target, "findings": []}
    elif choice == "all":
        selected = port_list
        enumerator = ServiceEnumerator(target, config)
        findings   = enumerator.enumerate(selected)
    else:
        try:
            indexes  = [int(x.strip()) for x in choice.split(",")]
            selected = [port_list[i - 1] for i in indexes if 1 <= i <= len(port_list)]
            enumerator = ServiceEnumerator(target, config)
            findings   = enumerator.enumerate(selected)
        except Exception:
            print("[!] Invalid selection — skipping enumeration.")
            findings = {"target": target, "findings": []}

    # Save full enumeration output to file — keeps console clean
    safe_target    = target.replace(".", "_")
    enum_filename  = f"{safe_target}_enumeration.json"
    with open(enum_filename, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] Enumeration saved to {enum_filename}")
    print(f"    View with: cat {enum_filename}\n")

    # Print one-line summary per port
    print("[+] Enumeration summary:")
    for f in findings.get("findings", []):
        status = "OK" if not f.get("error") else f"ERR: {f.get('error')}"
        print(f"    Port {f.get('port')} ({f.get('service')}) — {f.get('tool')} — {status}")

    # ----------------------------------------------------------------
    # Phase 4: NVD CVE lookup
    # NOW runs after enumeration — versions come from tool output,
    # not just nmap, so we get more accurate CVE matches
    # ----------------------------------------------------------------
    nvd           = NVDLookupStructured(results_per_page=5)
    software_list = nvd.build_software_list(scan_model)
    print(f"\n[+] Software list built with {len(software_list)} entries")

    cve_list = nvd.lookup_cves(software_list)
    print(f"[+] NVD lookup returned {len(cve_list)} CVE(s)")

    # ----------------------------------------------------------------
    # Phase 5: Ollama full analysis with enumeration + CVE context
    # ----------------------------------------------------------------
    findings_prompt = build_analysis_prompt(scan_model, cve_list)
    print("\n[~] Requesting full analysis from AI...")
    full_analysis = client.chat(findings_prompt)

    print("\n[+] Full AI Analysis:\n")
    print(full_analysis)

    # ----------------------------------------------------------------
    # Phase 6: AI test plan
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
    # Phase 7: Metasploit module intelligence
    # ----------------------------------------------------------------
    module_intel = ModuleIntel()
    print("\n[+] Metasploit module intelligence:\n")
    seen_cves = set()
    for cve in cve_list:
        cve_id = cve.get("cve_id")
        if not cve_id or cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        mods = module_intel.lookup_modules_by_cve(cve_id)
        if not mods:
            continue
        print(f"  CVE: {cve_id}")
        for m in mods:
            print(f"    Module: {m['name']}")
            print(f"    Type: {m['type']}")
            print(f"    Description: {m['description']}")

    # ----------------------------------------------------------------
    # Phase 8: GitHub PoC intelligence
    # ----------------------------------------------------------------
    poc_intel = PoCIntel(github_token=os.environ.get("GITHUB_TOKEN"))
    print("\n[+] GitHub PoC intelligence:\n")
    for cve in list(seen_cves)[:5]:
        pocs = poc_intel.search_pocs_for_cve(cve)
        if not pocs:
            continue
        print(f"  CVE: {cve}")
        for p in pocs:
            print(f"    Repo: {p['name']} ({p['html_url']})")
            print(f"    Stars: {p['stargazers_count']} — {p['description']}")

    # ----------------------------------------------------------------
    # Phase 9: Trim history to prevent context window bloat
    # ----------------------------------------------------------------
    client.trim_history(keep_pairs=2)

    print(f"\n[+] Complete. Files generated:")
    print(f"    {safe_target}_enumeration.json  — full enumeration data")


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
