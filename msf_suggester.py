import subprocess
import json

"""
msf_suggester.py

Searches msfconsole by CVE ID to get REAL module names, then uses
Ollama to explain and rank them. This flips the original approach
which asked Ollama to invent module names — causing hallucinations.

Flow:
    1. For each CVE, run: msfconsole -q -x "search cve:{id}; exit"
    2. Parse the real module names from that output
    3. Send real modules + CVE context to Ollama for ranking/explanation
    4. User selects modules
    5. Generate .rc script

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework
"""


class MSFSuggester:

    def __init__(self, target: str):
        self.target = target


    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, cve_list: list, findings: dict, client) -> list:
        if not cve_list:
            print("[!] No CVEs to search modules for.")
            return []

        # Step 1: Search msfconsole for real modules by CVE ID
        print("\n[+] Searching msfconsole for modules by CVE ID...")
        msf_results = self._search_msf_by_cve(cve_list)

        if not msf_results:
            print("[!] No Metasploit modules found for any CVE.")
            print("    Tip: This is normal — not every CVE has an msf module.")
            return []

        # Step 2: Ask Ollama to rank and explain the REAL modules we found
        print("\n[+] Asking Ollama to rank and explain found modules...")
        ranked = self._rank_with_ollama(msf_results, findings, client)

        if not ranked:
            ranked = msf_results   # fall back to unranked if Ollama fails

        # Step 3: User selects
        selected = self._user_select(ranked)

        if not selected:
            print("[+] No modules selected.")
            return []

        # Step 4: Generate .rc script
        self._generate_rc_script(selected)

        return selected


    # ------------------------------------------------------------------
    # Step 1: Search msfconsole by CVE ID
    # ------------------------------------------------------------------

    def _search_msf_by_cve(self, cve_list: list) -> list:
        """
        Runs msfconsole search for each unique CVE ID.
        Parses the real module names out of the output.
        Returns a list of dicts with confirmed module paths.
        """
        found = []
        seen_cves = set()

        for c in cve_list:
            cve_id = c.get("cve_id", "")

            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            print(f"  [~] Searching msf for: {cve_id}")

            try:
                result = subprocess.run(
                    ["msfconsole", "-q", "-x", f"search cve:{cve_id}; exit"],
                    capture_output=True,
                    text=True,
                    timeout=45
                )
                output = result.stdout

                # Parse module lines from msfconsole output
                # Real module lines look like:
                #   0  exploit/multi/http/apache_normalize_path_rce  ...
                modules = self._parse_msf_output(output)

                if modules:
                    print(f"      [+] Found {len(modules)} module(s)")
                    for m in modules:
                        found.append({
                            "cve_id":     cve_id,
                            "software":   c.get("software"),
                            "version":    c.get("version"),
                            "score":      c.get("score"),
                            "severity":   c.get("severity"),
                            "msf_module": m["path"],
                            "msf_rank":   m["rank"],
                            "msf_name":   m["name"],
                            "set_options": {
                                "RHOSTS": self.target
                            },
                            "reason":     "",    # Ollama fills this in step 2
                            "rank":       0      # Ollama fills this in step 2
                        })
                else:
                    print(f"      [-] No modules found")

            except subprocess.TimeoutExpired:
                print(f"      [!] msfconsole timed out for {cve_id}")
            except FileNotFoundError:
                print("[!] msfconsole not found. Is Metasploit installed?")
                print("    Install: sudo apt install metasploit-framework")
                break
            except Exception as e:
                print(f"      [!] Error: {e}")

        return found


    def _parse_msf_output(self, output: str) -> list:
        """
        Parses msfconsole search output into a list of module dicts.

        msfconsole search output looks like:
            Matching Modules
            ================

               #  Name                                          Disclosure Date  Rank       Check  Description
               -  ----                                          ---------------  ----       -----  -----------
               0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    ...
        """
        modules = []

        for line in output.splitlines():
            line = line.strip()

            # Skip headers, blank lines, decoration
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("="):
                continue
            if line.startswith("Matching") or line.startswith("Name") or line.startswith("No results"):
                continue

            parts = line.split()

            # Valid module lines start with a number index
            if not parts or not parts[0].isdigit():
                continue

            # Module path is always the second column
            if len(parts) >= 2:
                path = parts[1]

                # Validate it looks like a real module path
                if "/" in path and any(path.startswith(p) for p in [
                    "exploit/", "auxiliary/", "post/", "payload/"
                ]):
                    # Rank is usually 4th column
                    rank = parts[3] if len(parts) > 3 else "unknown"
                    # Name/description is everything after rank + check columns
                    name = " ".join(parts[5:]) if len(parts) > 5 else path.split("/")[-1]

                    modules.append({
                        "path": path,
                        "rank": rank,
                        "name": name
                    })

        return modules


    # ------------------------------------------------------------------
    # Step 2: Ollama ranks and explains the real modules
    # ------------------------------------------------------------------

    def _rank_with_ollama(self, msf_results: list, findings: dict, client) -> list:
        """
        Sends the confirmed module list to Ollama for ranking and
        explanation. Ollama cannot invent modules here — it can only
        rank and explain ones we already confirmed exist.
        """
        service_summary = ""
        for f in findings.get("findings", []):
            service_summary += f"  Port {f.get('port')} ({f.get('service')})\n"

        modules_summary = ""
        for i, m in enumerate(msf_results):
            modules_summary += (
                f"  {i+1}. {m['msf_module']}\n"
                f"     CVE: {m['cve_id']} ({m['software']} {m['version']}, "
                f"Score: {m['score']}, {m['severity']})\n"
                f"     MSF rank: {m['msf_rank']}\n\n"
            )

        prompt = f"""
You are a penetration testing assistant.

Target: {self.target}

Open services:
{service_summary}

The following Metasploit modules were confirmed to exist in msfconsole
by searching each CVE ID. These are REAL modules — do not change the paths.

Confirmed modules:
{modules_summary}

Return a JSON array ranking these modules by priority for this target.
Return ONLY the JSON array, no markdown, no extra text.

Each item must have:
- "rank": integer (1 = highest priority)
- "msf_module": exact module path from the list above (do not modify)
- "cve_id": the CVE ID
- "reason": one sentence why this module is high/low priority for this target
- "suggested_options": dict of any additional options beyond RHOSTS to set
  (e.g. {{"RPORT": "8080", "TARGETURI": "/app"}})
  Return empty dict {{}} if no additional options needed.
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
            ranked_list = json.loads(clean)

            # Merge Ollama's ranking back into our confirmed module dicts
            rank_map = {r.get("msf_module"): r for r in ranked_list}

            for m in msf_results:
                ollama_data = rank_map.get(m["msf_module"], {})
                m["rank"]   = ollama_data.get("rank", 99)
                m["reason"] = ollama_data.get("reason", "No explanation provided")

                # Merge any additional options Ollama suggested
                extra_opts = ollama_data.get("suggested_options", {})
                if extra_opts:
                    m["set_options"].update(extra_opts)

            return sorted(msf_results, key=lambda x: x.get("rank", 99))

        except Exception as e:
            print(f"[!] Could not parse Ollama ranking: {e}")
            return msf_results


    # ------------------------------------------------------------------
    # Step 3: User selects modules
    # ------------------------------------------------------------------

    def _user_select(self, suggestions: list) -> list:
        print("\n[+] Confirmed Metasploit modules:\n")

        for i, s in enumerate(suggestions, start=1):
            print(f"  {i}. [{s.get('severity', 'N/A')}] {s.get('cve_id')} — Score: {s.get('score')}")
            print(f"     Module  : {s.get('msf_module')}")
            print(f"     MSF rank: {s.get('msf_rank')}")
            print(f"     Reason  : {s.get('reason', 'Not ranked by Ollama')}\n")

        choice = input("Select modules for .rc script (e.g. 1,2 / 'all' / 'none'): ").strip().lower()

        if choice == "none":
            return []
        if choice == "all":
            return suggestions
        try:
            indexes = [int(x.strip()) for x in choice.split(",")]
            return [suggestions[i - 1] for i in indexes if 1 <= i <= len(suggestions)]
        except Exception:
            print("[!] Invalid selection.")
            return []


    # ------------------------------------------------------------------
    # Step 4: Generate .rc script
    # ------------------------------------------------------------------

    def _generate_rc_script(self, selected: list):
        safe_target = self.target.replace(".", "_")
        filename    = f"{safe_target}_modules.rc"

        lines = [
            "# xRECON generated Metasploit resource script",
            f"# Target: {self.target}",
            f"# Modules: {len(selected)}",
            "#",
            f"# Run with: msfconsole -r {filename}",
            "# IMPORTANT: Only run against authorized targets.",
            "",
        ]

        for s in selected:
            lines.append(f"# {s.get('cve_id')} — {s.get('reason', '')}")
            lines.append(f"# CVSSv3 Score: {s.get('score')} ({s.get('severity')})")
            lines.append(f"use {s.get('msf_module')}")

            options = s.get("set_options", {})
            if "RHOSTS" not in options:
                options["RHOSTS"] = self.target

            for option, value in options.items():
                lines.append(f"set {option} {value}")

            lines.append("run")
            lines.append("")

        try:
            with open(filename, "w") as f:
                f.write("\n".join(lines))
            print(f"\n[+] Resource script saved: {filename}")
            print(f"    Run with: msfconsole -r {filename}\n")
        except Exception as e:
            print(f"[!] Could not write .rc script: {e}")


    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def save_results(self, suggestions: list):
        safe_target = self.target.replace(".", "_")
        filename    = f"{safe_target}_msf_suggestions.json"
        try:
            with open(filename, "w") as f:
                json.dump(suggestions, f, indent=2)
            print(f"[+] MSF suggestions saved to {filename}")
        except Exception as e:
            print(f"[!] Could not save suggestions: {e}")
