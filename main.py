#!/usr/bin/env python3

import os
import json
import subprocess

from nmap_parser import NmapXMLParser
from nvd_lookup_structured import NVDLookupStructured
from prompts import build_analysis_prompt, build_test_plan_prompt
from ollama_client import Ollamaclient
from tester import Tester


def run_nmap_xml(target: str, xml_path: str = "scan.xml") -> bool:
    """
    Run Nmap with XML output so we can parse deterministically.
    """
    cmd = ["nmap", "-sV", "-oX", xml_path, target]
    print(f"[+] Running Nmap: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] Nmap not found. Is it installed and in PATH?")
        return False

    if result.returncode != 0:
        print("[!] Nmap scan failed:")
        print(result.stderr)
        return False

    print("[+] Nmap scan completed, XML saved to", xml_path)
    return True


def nmap_to_ai_structured(target: str, client: Ollamaclient):
    xml_path = "scan.xml"

    # 1) Run Nmap and produce XML
    if not run_nmap_xml(target, xml_path):
        return

    # 2) Parse Nmap XML into structured JSON model
    parser = NmapXMLParser(xml_path)
    scan_model = parser.parse()

    # Optional: quick sanity check
    host_count = len(scan_model.get("hosts", []))
    print(f"[+] Parsed scan model: {host_count} host(s)")

    # 3) NVD lookup based on structured model
    nvd = NVDLookupStructured(results_per_page=5)
    software_list = nvd.build_software_list(scan_model)
    print(f"[+] Built software list with {len(software_list)} entries")

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

    if not tests:
        print("[!] No tests suggested by AI.")
        return

    print("\n[+] Suggested tests:\n")
    for i, t in enumerate(tests, start=1):
        name = t.get("name")
        desc = t.get("description")
        port = t.get("port")
        print(f"{i}. {name} (port {port}) - {desc}")

    # 6) Human-in-the-loop selection
    choice = input("\nSelect tests to run (e.g., 'all', '1,3', or 'none'): ").strip().lower()

    if choice == "none":
        print("[*] No tests selected.")
        return

    if choice == "all":
        selected = tests
    else:
        indices = []
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(tests):
                    indices.append(idx - 1)
        if not indices:
            print("[!] No valid indices selected. Aborting test run.")
            return
        selected = [tests[i] for i in indices]

    # 7) Execute selected tests via Tester
    tester = Tester(target)
    for t in selected:
        name = t.get("name")
        port = t.get("port")
        print(f"\n[+] Running test: {name} (port {port})")
        # You can later extend Tester.run_test to accept port or context
        result = tester.run_test(name)
        print(result)


def main():
    # Configure Ollama client
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
