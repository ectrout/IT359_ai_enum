import os
import time
import nvdlib
from typing import List, Dict, Any


class NVDLookupStructured:
    def __init__(self, results_per_page: int = 5):
        self.api_key = os.environ.get("NVD_API_KEY")
        self.results_per_page = results_per_page
        self.delay = 1 if self.api_key else 7

        if self.api_key:
            print("[+] NVD API key found — fast mode (1s delay)")
        else:
            print("[!] No NVD API key — rate-limited mode (7s delay)")
            print("    Get a free key: https://nvd.nist.gov/developers/request-an-api-key")

    def build_software_list(self, scan_model: Dict[str, Any]) -> List[Dict[str, str]]:
        items = []
        for host in scan_model.get("hosts", []):
            for port in host.get("ports", []):
                product = port.get("product")
                version = port.get("version")
                service = port.get("service")
                portid = port.get("port")

                # Keep entries even if version is missing
                items.append({
                    "service": service,
                    "product": product,
                    "version": version,
                    "port": portid,
                })
        return items

    def lookup_cves(self, software_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        all_cves = []

        for item in software_list:
            product = (item.get("product") or "").strip()
            version = (item.get("version") or "").strip()
            service = (item.get("service") or "").strip()
            port = item.get("port")

            # If we have neither product nor service, skip
            if not product and not service:
                continue

            # Build a reasonable keyword query
            if product and version:
                query = f"{product} {version}"
            elif product:
                query = product
            elif service and version:
                query = f"{service} {version}"
            else:
                query = service

            print(f"  [~] Querying NVD for: {query} (port {port})")

            try:
                results = nvdlib.searchCVE(
                    keywordSearch=query,
                    limit=self.results_per_page,
                    key=self.api_key,
                    delay=self.delay,
                )

                for r in results:
                    score = None
                    severity = None

                    if getattr(r, "v31score", None):
                        score = r.v31score
                        severity = getattr(r, "v31severity", None)
                    elif getattr(r, "v30score", None):
                        score = r.v30score
                        severity = getattr(r, "v30severity", None)
                    elif getattr(r, "v2score", None):
                        score = r.v2score
                        severity = getattr(r, "v2severity", None)

                    description = ""
                    if getattr(r, "descriptions", None):
                        for d in r.descriptions:
                            if d.lang == "en":
                                description = d.value
                                break

                    all_cves.append({
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version or None,
                        "cve_id": r.id,
                        "score": score,
                        "severity": severity,
                        "description": description,
                        "query": query,
                    })

                if results:
                    print(f"    [+] Found {len(results)} CVE(s) for {query}")
                else:
                    print(f"    [-] No CVEs found for {query}")

            except Exception as e:
                print(f"    [!] NVD query failed for {query}: {e}")

        # Sort by score descending, None last
        all_cves.sort(key=lambda x: x.get("score") or 0, reverse=True)
        return all_cves
