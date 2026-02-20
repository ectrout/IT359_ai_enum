from nmap_scan import NmapScan
from ollama_client import Ollamaclient
import os

def nmap_to_ai(target):
    print(f"[+] Starting Nmap scan on {target}")

    #1.) lets run Nmap
    scanner = NmapScan(target)
    scanner.run()

    nmap_output = scanner.get_output()

    if not nmap_output:
        print(f"[-] No output from Nmap. Exiting...")
        return
    
    print("[+] Scan complete. Preparing AI analysis... \n")

    #2.) intialize the ollama client
    client = Ollamaclient(
        url = 'http://sushi.it.ilstu.edu:8080',
        api_key = os.environ.get('API_KEY'),   #Retrive the API key from the operating system environment
        model="llama3.3:latest"     # Can be changed to a model of your liking
    )

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


if __name__ == "__main__":
    #Enter Target in " " notation
    #Example: nmap_to_ai("192.168.1.0")
    nmap_to_ai("")
