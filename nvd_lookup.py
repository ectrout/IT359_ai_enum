import nvdlib
import json
import time

"""
nvd_lookup.py

Queries the NVD using nvdlib — a proper Python wrapper that handles
rate limiting, key names, and response parsing automatically.

Replaces the raw requests approach which had fragile key name assumptions
and was hitting NVD rate limits silently.

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework

Install: pip install nvdlib
"""


class NVDLookup:

    def __init__(self, api_key: str = api_key, results_per_page: int = 5):
        """
        api_key — optional NVD API key from https://nvd.nist.gov/developers/request-an-api-key
                  Free, takes 1 minute to get. Without it nvdlib sleeps 6 seconds between
                  requests automatically to respect rate limits.
        """
        self.api_key       = os.environ.get('NVD_API_KEY', 'default_value')
        self.results_per_page = results_per_page


    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, findings: dict, client) -> list:
        """
        Full pipeline:
            1. Ask Ollama to extract software/version pairs from findings
            2. Query NVD via nvdlib for each pair
            3. Return sorted CVE list (highest score first)
        """
        print("\n[+] Extracting software versions via Ollama...")
        version_list = self.extract_versions(findings, client)

        if not version_list:
            print("[!] No software versions extracted. Skipping NVD lookup.")
            return []

        print(f"[+] Found {len(version_list)} software version(s). Querying NVD...\n")
        cve_list = self.lookup_cves(version_list)

        if not cve_list:
            print("[!] No CVEs found for detected software.")
            return []

        cve_list.sort(key=lambda x: x.get("score") or 0, reverse=True)
        return cve_list


    # ------------------------------------------------------------------
    # Step 1: Ollama extracts version strings
    # ------------------------------------------------------------------

    def extract_versions(self, findings: dict, client) -> list:
        """
        Sends enumeration output to Ollama and asks it to extract
        software names and version numbers as structured JSON.
        """
        output_text = ""
        for finding in findings.get("findings", []):
            port    = finding.get("port")
            service = finding.get("service")
            output  = finding.get("output", "")
            if api_key: str = none
                time.sleep(6) 
            if output:
                output_text += f"\nPort {port} ({service}):\n{output}\n"

        if not output_text.strip():
            print("[!] No enumeration output to extract versions from.")
            return []

        prompt = f"""
Extract all software names and version numbers from the following
enumeration output. Return ONLY a JSON array with no extra text,
no markdown, and no code fences.

Each item must have exactly two keys: "software" and "version".

Example format:
[
    {{"software": "Apache", "version": "2.4.49"}},
    {{"software": "OpenSSH", "version": "7.4"}}
]

If no version numbers are found, return an empty array: []

Enumeration output:
{output_text}
"""
        response = client.chat(prompt)

        try:
            clean = (
                response.strip()
                .removeprefix("```json")
                .removeprefix("```")
                .removesuffix("```")
                .strip()
            )
            return json.loads(clean)
        except Exception as e:
            print(f"[!] Could not parse version JSON from Ollama: {e}")
            print(f"    Raw response: {response[:200]}")
            return []


    # ------------------------------------------------------------------
    # Step 2: Query NVD via nvdlib
    # ------------------------------------------------------------------

    def lookup_cves(self, version_list: list) -> list:
        """
        Uses nvdlib.searchCVE() to query NVD for each software/version pair.
        nvdlib handles rate limiting automatically — 6 second sleep between
        requests without an API key, 0.6 seconds with one.
        """
        all_cves = []

        for item in version_list:
            software = item.get("software", "").strip()
            version  = item.get("version", "").strip()

            if not software or not version:
                continue

            query = f"{software} {version}"
            print(f"  [~] Querying NVD for: {query}")

            try:
                results = nvdlib.searchCVE(
                    keywordSearch=query,
                    limit=self.results_per_page,
                    key=self.api_key,
                    delay=1 if self.api_key else 6
                )

                for r in results:
                    # Pull score — nvdlib exposes v31score, v30score, v2score
                    score    = None
                    severity = None

                    if hasattr(r, 'v31score') and r.v31score:
                        score    = r.v31score
                        severity = r.v31severity if hasattr(r, 'v31severity') else None
                    elif hasattr(r, 'v30score') and r.v30score:
                        score    = r.v30score
                        severity = r.v30severity if hasattr(r, 'v30severity') else None
                    elif hasattr(r, 'v2score') and r.v2score:
                        score    = r.v2score
                        severity = r.v2severity if hasattr(r, 'v2severity') else None

                    # Pull description
                    description = ""
                    if hasattr(r, 'descriptions') and r.descriptions:
                        for d in r.descriptions:
                            if d.lang == "en":
                                description = d.value
                                break

                    all_cves.append({
                        "software":    software,
                        "version":     version,
                        "cve_id":      r.id,
                        "score":       score,
                        "severity":    severity,
                        "description": description[:500]
                    })

                if results:
                    print(f"    [+] Found {len(results)} CVE(s) for {query}")
                else:
                    print(f"    [-] No CVEs found for {query}")

            except Exception as e:
                print(f"    [!] NVD query failed for {query}: {e}")

        return all_cves


    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def save_results(self, cve_list: list, target: str, filename: str = None):
        if filename is None:
            safe_target = target.replace(".", "_")
            filename    = f"{safe_target}_cves.json"
        try:
            with open(filename, "w") as f:
                json.dump(cve_list, f, indent=2)
            print(f"\n[+] CVE results saved to {filename}")
        except Exception as e:
            print(f"[!] Could not save CVE results: {e}")
