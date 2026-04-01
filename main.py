from nmap_scan import NmapScan
from ollama_client import Ollamaclient
from tester import Tester
import os
import json


def nmap_to_ai(target, client):
    print(f"[+] Starting Nmap scan on {target}")

    #1.) lets run Nmap
    scanner = NmapScan(target)
    scanner.run()

    nmap_output = scanner.get_output()

    if not nmap_output:
        print(f"[-] No output from Nmap. Exiting...")
        return
    
    print("[+] Scan complete. Preparing AI analysis... \n")

    #3.1) Summarize the scan 
    summary_prompt = f"""
Summarize the following Nmap scan in 5 bullet points.
Do NOT repeat text. Do NOT include recommendations.

Nmap Output:
{nmap_output}
"""

    summary = client.chat(summary_prompt)

    # 4. Store ONLY the summary in long-term memory
    client.remember(f"Summary for {target}:\n{summary}")

    #5.) Now ask for full anlysis using the history 

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
    
    #Fourth Send output to Ai 
    analysis = client.chat(analysis_prompt)

    print("\n[+] AI Analysis: \n")
    print(analysis)

    #Next Step prompt
    next_step_prompt = f"""
    Based on this analysis, return ONLY a JSON object WITH:
    "tests": [
    {{"name": "short test name", "description": "what to check", "target": "{target}"}}
    ]
    Do NOT include any code. Do NOT include any commands. High-level test descriptions only. 

    Analysis:
    {analysis}
    """
    next_step_json = client.chat(next_step_prompt)

    print("\n[+] Recommended Follow Up Tests:\n")
    print(next_step_json)

    try:
        parsed = json.loads(next_step_json)
        tests = parsed.get("tests", [])
    except Exception as e:
        print(f"[!] Could not parse JSON: {e}")
        return
    if not tests:
        print("[!] No tests returned by Ai.")
        return 

    
    #User selects tests to run | Keeping Humans involved. 
    print("\n[+] Test menu:\n")
    for i, t in enumerate(tests, start=1):
        print(f"{i}.  {t['name']} - {t['description']}")
    
    choice = input("\nSelect tests to run (e.g., 1,2,'all', or 'none')").strip().lower()
    #Now determine test logic
    if choice == "none":
        print("[+] No test(s) selected. Returning to prompt.\n")
        return
    if choice == "all":
        print("[+] All tests selected")
        selected_tests = tests
    else:
        try:
            indexes = [int(x.strip()) for x in choice.split(",")]
            selected_tests = [tests[i-1] for i in indexes if 1 <= i <= len(tests)]
        except:
            print("[!] Invalid selection. No tests will be run. \n")
            return 

    tester = Tester(target)

    for t in selected_tests:
        name = t["name"]
        print(f"\n[+] Running test: {name}")
        result = tester.run_test(name)
        print(result)



if __name__ == "__main__":
    #Enter Target in " " notation
    #Example: nmap_to_ai("192.168.1.0",client)
    client = Ollamaclient(
        url = 'http://sushi.it.ilstu.edu:8080',
        api_key = os.environ.get('API_KEY'),   #Retrive the API key from the operating system environment
        model="llama3.3:latest"     # Can be changed to a model of your liking
    )

    while True:
        target = input("Enter target IP (or 'exit'): ").strip().lower()
        if target == "exit":
            break
        if target == "reset":
            client.reset()
            print("[+] Ai memory has been reset. Ready for next command...\n")
            continue
        if target:
            nmap_to_ai(target,client)
