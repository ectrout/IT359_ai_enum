import json
from typing import List, Dict, Any, Optional


class ModuleIntel:
    def __init__(self, json_path: str = "metasploit_modules.json"):
        self.json_path = json_path
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.json_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {"modules": []}

    def lookup_modules_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        cve_id = cve_id.upper()
        return [
            m for m in self.data.get("modules", [])
            if cve_id in [c.upper() for c in m.get("cves", [])]
        ]

    def lookup_module_metadata(self, module_name: str) -> Optional[Dict[str, Any]]:
        for m in self.data.get("modules", []):
            if m.get("name") == module_name:
                return m
        return None

    def lookup_module_options(self, module_name: str) -> Dict[str, str]:
        meta = self.lookup_module_metadata(module_name)
        if not meta:
            return {}
        return meta.get("options", {})
