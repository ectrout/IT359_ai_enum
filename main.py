#!/usr/bin/env python3

import os
import json
import subprocess

from nmap_parser import NmapXMLParser
from nvd_lookup_structured import NVDLookupStructured
from prompts import build_analysis_prompt, build_test_plan_prompt
from ollama_client import Ollamaclient
from service_enum import service_enum   # You said you still use this


def run_nmap_xml(target: str, xml_path: str = "scan.xml") -> bool:
    """
    Run Nmap with XML output so we can parse deterministically.
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

    # 1) Run Nmap and produce XML
    if not run_nmap_xml(target, xml_path):
        return

    # 2) Parse Nmap XML into structured JSON model
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

    # 4) AI analysis (human-readable)
    analysis_prompt = build_analysis_prompt(scan_model, cve_list)
    print("\n[~] Sending analysis prompt to AI...")
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis:\n")
    print(analysis)

    # 5) AI test plan (JSON)
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
        return

    print("\n[+] Suggested next steps:\n")
    if not tests:
        print("[!] AI did not suggest any tests.")
    else:
        for i, t in enumerate(tests, start=1):
            name = t.get("name")
            desc = t.get("description")
            port = t.get("port")
            print(f"{i}. {name} (port {port}) - {desc}")

    print("\n[*] Automated exploitation is disabled.")
    print("[*] These suggestions are for manual recon guidance.\n")

    # 6) Deterministic service enumeration
    print("[+] Running deterministic service enumeration...\n")
    enum_results = service_enum(scan_model)

    print("[+] Service Enumeration Results:\n")
    print(enum_results)
    print("\n[*] Enumeration complete.\n")


def main():
    client = Ollamaclient(
        url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        api_key=os.environ.get("API_KEY"),
        model=os.environ.get("OLLAMA_MODEL", "llama3.3:latest"),
    )

    print("[+] IT359 AI Enum — Structured Mode")
    print("    Type 'reset' to reset AI context, 'exit' to quit.\n")

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
