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
from module_intel import ModuleIntel
from poc_intel import PoCIntel
from update_module_metadata import main as update_modules


def run_nmap_xml(target: str, xml_path: str = "scan.xml") -> bool:
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

    # 1) Nmap XML
    if not run_nmap_xml(target, xml_path):
        return

    # 2) Parse XML → structured model
    parser = NmapXMLParser(xml_path)
    scan_model = parser.parse()
    host_count = len(scan_model.get("hosts", []))
    print(f"[+] Parsed scan model: {host_count} host(s) detected")

    # 3) NVD lookup
    nvd = NVDLookupStructured(results_per_page=5)
    software_list = nvd.build_software_list(scan_model)
    print(f"[+] Software list built with {len(software_list)} entries")

    cve_list = nvd.lookup_cves(software_list)
    print(f"[+] NVD lookup returned {len(cve_list)} CVE(s)")

    # 4) AI analysis
    analysis_prompt = build_analysis_prompt(scan_model, cve_list)
    print("\n[~] Sending analysis prompt to AI...")
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # 5) AI next-step suggestions (JSON)
    test_plan_prompt = build_test_plan_prompt(scan_model, cve_list, target)
    print("\n[~] Requesting test plan from AI...")
    test_plan_raw = client.chat(test_plan_prompt)

    try:
        test_plan = json.loads(test_plan_raw)
        tests = test_plan.get("tests", [])
    except Exception as e:
        print(f"[!] Could not parse test plan JSON: {e}")
        print("[DEBUG] Raw AI response:")
        print(test_plan_raw)
        tests = []

    print("\n[+] Suggested next steps (manual recon only):\n")
    if not tests:
        print("[!] AI did not suggest any tests.")
    else:
        for i, t in enumerate(tests, start=1):
            name = t.get("name")
            desc = t.get("description")
            port = t.get("port")
            print(f"{i}. {name} (port {port}) - {desc}")

    print("\n[*] Automated exploitation is disabled. Use suggestions as guidance only.\n")

    # 6) Metasploit module intelligence (metadata only)
    module_intel = ModuleIntel()
    print("[+] Metasploit module intelligence (metadata only):\n")
    seen_cves = set()
    for cve in cve_list:
        cve_id = cve.get("cve_id")
        if not cve_id or cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        mods = module_intel.lookup_modules_by_cve(cve_id)
        if not mods:
            continue
        print(f"CVE: {cve_id}")
        for m in mods:
            print(f"  Module: {m['name']}")
            print(f"    Type: {m['type']}")
            print(f"    Description: {m['description']}")
            print(f"    Options:")
            for opt, desc in m.get("options", {}).items():
                print(f"      - {opt}: {desc}")
        print()

    # 7) GitHub PoC intelligence (metadata only)
    poc_intel = PoCIntel(github_token=os.environ.get("GITHUB_TOKEN"))
    print("[+] GitHub PoC intelligence (metadata only):\n")
    for cve in list(seen_cves)[:5]:
        pocs = poc_intel.search_pocs_for_cve(cve)
        if not pocs:
            continue
        print(f"CVE: {cve}")
        for p in pocs:
            print(f"  Repo: {p['name']} ({p['html_url']})")
            print(f"    Desc: {p['description']}")
            print(f"    Lang: {p['language']}, Stars: {p['stargazers_count']}")
            print(f"    Note: {p['what_it_demonstrates']}")
        print()

    # 8) Deterministic service enumeration
    print("[+] Running deterministic service enumeration...\n")
    enum_results = service_enum(scan_model)
    print("[+] Service Enumeration Results:\n")
    print(enum_results)
    print("\n[*] Enumeration complete.\n")


def main():
    if "--update-modules" in sys.argv:
        update_modules()
        return

    client = Ollamaclient(
        url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        api_key=os.environ.get("API_KEY"),
        model=os.environ.get("OLLAMA_MODEL", "llama3.3:latest"),
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
