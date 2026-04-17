import requests
from typing import List, Dict, Any


class PoCIntel:
    def __init__(self, github_token: str | None = None):
        self.github_token = github_token

    def search_pocs_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Metadata only: search GitHub for repos mentioning the CVE.
        """
        headers = {}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        query = f'"{cve_id}" in:name,description,readme'
        url = "https://api.github.com/search/repositories"
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": 5}

        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code != 200:
            return []

        items = resp.json().get("items", [])
        results = []
        for repo in items:
            results.append({
                "name": repo.get("full_name"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description"),
                "language": repo.get("language"),
                "stargazers_count": repo.get("stargazers_count"),
                "what_it_demonstrates": f"Repository mentioning {cve_id}; review code and docs for PoC details.",
            })
        return results
