import requests
import json
import time

"""
nvd_lookup.py

Queries the NIST National Vulnerability Database (NVD) REST API
to cross-reference software versions found during enumeration with
known CVEs. Uses Ollama to extract version strings from raw findings
rather than brittle regex.

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
"""


class NVDLookup:

    def __init__(self, timeout: int = 10, results_per_page: int = 5):
        self.base_url        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.timeout         = timeout
        self.results_per_page = results_per_page


    # ------------------------------------------------------------------
    # Public entry point — call this from main.py
    # ------------------------------------------------------------------

    def run(self, findings: dict, client) -> list:
        """
        Full pipeline:
            1. Ask Ollama to extract software/version pairs from findings
            2. Query NVD for each pair
            3. Return sorted CVE list (highest score first)

        findings  — the dict returned by ServiceEnumerator.enumerate()
        client    — your Ollamaclient instance
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

        # Sort by CVSS score descending so highest risk is first
        cve_list.sort(key=lambda x: x.get("score") or 0, reverse=True)

        return cve_list


    # ------------------------------------------------------------------
    # Step 1: Use Ollama to extract version strings from findings
    # ------------------------------------------------------------------

    def extract_versions(self, findings: dict, client) -> list:
        """
        Sends enumeration output to Ollama and asks it to extract
        software names and version numbers as structured JSON.

        Returns:
            [
                {"software": "Apache", "version": "2.4.49"},
                {"software": "OpenSSH", "version": "7.4"}
            ]
        """
        # Pull just the output strings from each finding, labeled by port
        output_text = ""
        for finding in findings.get("findings", []):
            port    = finding.get("port")
            service = finding.get("service")
            output  = finding.get("output", "")
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
    # Step 2: Query NVD for each software/version pair
    # ------------------------------------------------------------------

    def lookup_cves(self, version_list: list) -> list:
        """
        Queries NVD API for each {software, version} dict.
        Returns a flat list of CVE dicts with score and severity.

        Each result looks like:
            {
                "software":    "Apache",
                "version":     "2.4.49",
                "cve_id":      "CVE-2021-41773",
                "score":       9.8,
                "severity":    "CRITICAL",
                "description": "A path traversal vulnerability..."
            }
        """
        all_cves = []

        for item in version_list:
            software = item.get("software", "")
            version  = item.get("version", "")

            if not software or not version:
                continue

            query = f"{software} {version}"
            print(f"  [~] Querying NVD for: {query}")

            cves = self._query_nvd(query, software, version)
            all_cves.extend(cves)

            # NVD rate limit: 5 requests per 30 seconds without API key
            # Sleep briefly between requests to avoid getting blocked
            time.sleep(1)

        return all_cves


    # ------------------------------------------------------------------
    # NVD API call
    # ------------------------------------------------------------------

    def _query_nvd(self, query: str, software: str, version: str) -> list:
        """
        Makes a single request to the NVD API and parses the response.
        Returns a list of CVE dicts for this software/version pair.
        """
        params = {
            "keywordSearch":  query,
            "resultsPerPage": self.results_per_page
        }

        try:
            response = requests.get(
                self.base_url,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

        except requests.exceptions.Timeout:
            print(f"    [!] NVD request timed out for: {query}")
            return []
        except requests.exceptions.RequestException as e:
            print(f"    [!] NVD request failed for {query}: {e}")
            return []
        except Exception as e:
            print(f"    [!] Unexpected error querying NVD: {e}")
            return []

        # Parse each CVE out of the response
        results = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})

            cve_id = cve.get("id", "UNKNOWN")

            # Pull description (first English one)
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Try CVSS v3.1 first, fall back to v2
            score    = None
            severity = None

            metrics = cve.get("metrics", {})

            if metrics.get("cvssMetricV31"):
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore")
                severity  = cvss_data.get("baseSeverity")

            elif metrics.get("cvssMetricV2"):
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                score     = cvss_data.get("baseScore")
                severity  = cvss_data.get("baseSeverity", "N/A")

            results.append({
                "software":    software,
                "version":     version,
                "cve_id":      cve_id,
                "score":       score,
                "severity":    severity,
                "description": description[:300]   # truncate so it doesn't flood Ollama
            })

        if results:
            print(f"    [+] Found {len(results)} CVE(s) for {query}")
        else:
            print(f"    [-] No CVEs found for {query}")

        return results


    # ------------------------------------------------------------------
    # Export results to JSON file
    # ------------------------------------------------------------------

    def save_results(self, cve_list: list, target: str, filename: str = None):
        """
        Saves the CVE list to a JSON file.
        Filename defaults to {target}_cves.json
        """
        if filename is None:
            safe_target = target.replace(".", "_")
            filename    = f"{safe_target}_cves.json"

        try:
            with open(filename, "w") as f:
                json.dump(cve_list, f, indent=2)
            print(f"\n[+] CVE results saved to {filename}")
        except Exception as e:
            print(f"[!] Could not save CVE results: {e}")
