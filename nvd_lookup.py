import os
import time
import requests


class NVDLookupStructured:
    def __init__(self, results_per_page=5):
        self.api_key = os.environ.get("NVD_API_KEY")
        self.results_per_page = results_per_page
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        if self.api_key:
            print("[+] NVD API key loaded — fast mode (1s delay)")
            self.delay = 1
        else:
            print("[!] No NVD API key — rate-limited mode (7s delay)")
            self.delay = 7

    # ------------------------------------------------------------
    # CPE BUILDER (simple + effective)
    # ------------------------------------------------------------
    def guess_cpe(self, product: str, version: str):
        """
        Convert product/version into a simple CPE guess.
        Example:
            product="ProFTPD", version="1.3.5"
            → cpe:/a:proftpd:proftpd:1.3.5
        """
        if not product or not version:
            return None

        p = product.lower().replace(" ", "_")
        return f"cpe:/a:{p}:{p}:{version}"

    # ------------------------------------------------------------
    # MAIN LOOKUP
    # ------------------------------------------------------------
    def lookup_cves(self, software_list):
        results = []

        for entry in software_list:
            product = entry.get("product")
            version = entry.get("version")
            port = entry.get("port")

            # Skip empty entries
            if not product or not version:
                print(f"[!] Skipping empty product/version for port {port}")
                continue

            # Build CPE
            cpe = self.guess_cpe(product, version)
            if not cpe:
                print(f"[!] Could not build CPE for {product} {version}")
                continue

            print(f"[~] Querying NVD for CPE: {cpe} (port {port})")

            params = {
                "cpeName": cpe,
                "resultsPerPage": self.results_per_page
            }

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=10
                )

                # Debug: show the exact URL used
                print("[DEBUG] URL:", response.url)

                response.raise_for_status()
                data = response.json()

                cve_items = data.get("vulnerabilities", [])
                for item in cve_items:
                    cve_id = item.get("cve", {}).get("id")
                    if cve_id:
                        results.append({
                            "cve_id": cve_id,
                            "product": product,
                            "version": version,
                            "port": port
                        })

            except requests.exceptions.HTTPError as e:
                print(f"[!] HTTP error for {product} {version}: {e}")
            except Exception as e:
                print(f"[!] Error querying NVD for {product} {version}: {e}")

            time.sleep(self.delay)

        return results

    # ------------------------------------------------------------
    # Build software list from structured scan model
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
