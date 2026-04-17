import os
import time
import requests
from difflib import SequenceMatcher


class NVDLookupStructured:
    def __init__(self, results_per_page=5):
        self.api_key = os.environ.get("NVD_API_KEY")
        self.results_per_page = results_per_page
        self.base_cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.base_cpe_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

        if self.api_key:
            print("[+] NVD API key loaded — fast mode (1s delay)")
            self.delay = 1
        else:
            print("[!] No NVD API key — rate-limited mode (7s delay)")
            self.delay = 7

    # ------------------------------------------------------------
    # SMART CPE MATCHING (Option B)
    # ------------------------------------------------------------
    def find_best_cpe(self, product, version):
        """
        Query NVD CPE API and pick the best matching CPE.
        """
        params = {"keywordSearch": product}
        headers = {"apiKey": self.api_key} if self.api_key else {}

        try:
            resp = requests.get(self.base_cpe_url, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[!] CPE lookup failed for {product}: {e}")
            return None

        items = data.get("products", [])
        if not items:
            print(f"[!] No CPE candidates found for {product}")
            return None

        # Score candidates
        best_score = 0
        best_cpe = None

        for item in items:
            cpe = item.get("cpe", {}).get("cpeName")
            if not cpe:
                continue

            # Extract vendor/product/version from CPE
            parts = cpe.split(":")
            if len(parts) < 5:
                continue

            vendor = parts[3]
            prod = parts[4]
            cpe_version = parts[5] if len(parts) > 5 else ""

            # Similarity scoring
            score = 0
            score += SequenceMatcher(None, product.lower(), prod.lower()).ratio() * 0.6
            score += SequenceMatcher(None, product.lower(), vendor.lower()).ratio() * 0.3

            # Version match bonus
            if version and version.split(".")[0] in cpe_version:
                score += 0.3

            if score > best_score:
                best_score = score
                best_cpe = cpe

        if best_cpe:
            print(f"[+] Best CPE match for {product} {version}: {best_cpe}")
        else:
            print(f"[!] No suitable CPE match for {product} {version}")

        return best_cpe

    # ------------------------------------------------------------
    # MAIN CVE LOOKUP
    # ------------------------------------------------------------
    def lookup_cves(self, software_list):
        results = []

        for entry in software_list:
            product = entry.get("product")
            version = entry.get("version")
            port = entry.get("port")

            if not product:
                print(f"[!] Skipping empty product for port {port}")
                continue

            print(f"\n[~] Resolving CPE for: {product} {version} (port {port})")
            cpe = self.find_best_cpe(product, version)

            if not cpe:
                print(f"[!] No CPE found for {product} {version}")
                continue

            params = {
                "cpeName": cpe,
                "resultsPerPage": self.results_per_page
            }
            headers = {"apiKey": self.api_key} if self.api_key else {}

            try:
                resp = requests.get(self.base_cve_url, params=params, headers=headers, timeout=10)
                print("[DEBUG] CVE URL:", resp.url)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"[!] CVE lookup failed for {product} {version}: {e}")
                continue

            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                cve_id = v.get("cve", {}).get("id")
                if cve_id:
                    results.append({
                        "cve_id": cve_id,
                        "product": product,
                        "version": version,
                        "port": port
                    })

            time.sleep(self.delay)

        return results

    # ------------------------------------------------------------
    # Build software list from scan model
    # ------------------------------------------------------------
    def build_software_list(self, scan_model):
        software = []
        for host in scan_model.get("hosts", []):
            for svc in host.get("services", []):
                software.append({
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "port": svc.get("port")
                })
        return software
