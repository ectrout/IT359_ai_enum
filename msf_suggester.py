import subprocess
import json
import os

"""
msf_suggester.py

Takes the CVE list from nvd_lookup.py and uses Ollama to suggest
relevant Metasploit modules for each finding. Validates suggestions
against real msfconsole search results, then generates a .rc script
the operator can run directly.

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework

Usage in main.py:
    from msf_suggester import MSFSuggester
    msf = MSFSuggester(target)
    suggestions = msf.run(cve_list, findings, client)
"""


class MSFSuggester:

    def __init__(self, target: str):
        self.target = target


    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, cve_list: list, findings: dict, client) -> list:
        """
        Full pipeline:
            1. Ask Ollama to suggest Metasploit modules for each CVE
            2. Validate each suggestion against real msfconsole search
            3. Let user select which modules to include
            4. Generate .rc script for selected modules
            5. Return final validated suggestion list

        cve_list  — output from NVDLookup.run()
        findings  — output from ServiceEnumerator.enumerate()
        client    — your Ollamaclient instance
        """
        if not cve_list:
            print("[!] No CVEs to suggest modules for.")
            return []

        # Step 1: Ask Ollama for module suggestions
        print("\n[+] Asking Ollama for Metasploit module suggestions...")
        suggestions = self._get_suggestions(cve_list, findings, client)

        if not suggestions:
            print("[!] Ollama returned no module suggestions.")
            return []

        # Step 2: Validate each suggestion against msfconsole
        print("\n[+] Validating modules against msfconsole...\n")
        validated = self._validate_suggestions(suggestions)

        if not validated:
            print("[!] No suggestions survived validation.")
            return []

        # Step 3: Show operator the validated list and let them choose
        selected = self._user_select(validated)

        if not selected:
            print("[+] No modules selected.")
            return []

        # Step 4: Generate the .rc script
        self._generate_rc_script(selected)

        return selected


    # ------------------------------------------------------------------
    # Step 1: Ollama suggests modules
    # ------------------------------------------------------------------

    def _get_suggestions(self, cve_list: list, findings: dict, client) -> list:
        """
        Sends CVE list and enumeration context to Ollama.
        Asks for exact Metasploit module paths and required options.
        """
        # Build a compact summary of findings for context
        service_summary = ""
        for f in findings.get("findings", []):
            service_summary += f"  Port {f.get('port')} ({f.get('service')})\n"

        # Build compact CVE summary
        cve_summary = ""
        for c in cve_list[:10]:   # cap at 10 to keep prompt reasonable
            cve_summary += (
                f"  {c.get('cve_id')} — {c.get('software')} {c.get('version')} "
                f"(Score: {c.get('score')}, {c.get('severity')})\n"
                f"  {c.get('description', '')[:150]}\n\n"
            )

        prompt = f"""
You are a penetration testing assistant helping suggest Metasploit modules.

Target: {self.target}

Open services:
{service_summary}

CVEs found:
{cve_summary}

For each CVE that has a known Metasploit module, return a JSON array.
Return ONLY the JSON array, no extra text, no markdown, no code fences.

Each item must have exactly these keys:
- "rank": integer starting at 1 (1 = highest priority)
- "cve_id": the CVE ID string
- "software": software name
- "port": integer port number
- "service": service name
- "msf_module": exact Metasploit module path (e.g. "exploit/multi/http/apache_normalize_path_rce") or null if unknown
- "set_options": dict of required options e.g. {{"RHOSTS": "{self.target}", "RPORT": "80"}}
- "reason": one sentence explaining why this module applies

Only include CVEs where you are confident a real Metasploit module exists.
If no modules apply, return an empty array: []
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
            print(f"[!] Could not parse Ollama module suggestions: {e}")
            print(f"    Raw response: {response[:300]}")
            return []


    # ------------------------------------------------------------------
    # Step 2: Validate suggestions against msfconsole
    # ------------------------------------------------------------------

    def _validate_suggestions(self, suggestions: list) -> list:
        """
        For each suggested module, runs:
            msfconsole -q -x "search cve:{cve_id}; exit"

        Checks whether the suggested module path appears in the results.
        Marks each suggestion as validated or unvalidated.
        Keeps both — but flags unvalidated ones clearly so the operator knows.
        """
        validated = []

        for s in suggestions:
            cve_id     = s.get("cve_id", "")
            msf_module = s.get("msf_module")

            if not msf_module:
                s["validated"] = False
                s["validation_note"] = "No module suggested by Ollama"
                validated.append(s)
                continue

            print(f"  [~] Checking: {msf_module} ({cve_id})")

            try:
                result = subprocess.run(
                    ["msfconsole", "-q", "-x", f"search cve:{cve_id}; exit"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout.lower()

                # Check if the suggested module path appears in search results
                module_short = msf_module.lower().split("/")[-1]

                if msf_module.lower() in output or module_short in output:
                    s["validated"]       = True
                    s["validation_note"] = "Confirmed in msfconsole search"
                    print(f"      [+] Validated")
                else:
                    s["validated"]       = False
                    s["validation_note"] = "Module not found in msfconsole search — verify manually"
                    print(f"      [!] Not confirmed — flagged for manual review")

            except subprocess.TimeoutExpired:
                s["validated"]       = False
                s["validation_note"] = "msfconsole validation timed out"
                print(f"      [!] Validation timed out")
            except FileNotFoundError:
                s["validated"]       = False
                s["validation_note"] = "msfconsole not found — install Metasploit"
                print(f"      [!] msfconsole not installed")
            except Exception as e:
                s["validated"]       = False
                s["validation_note"] = str(e)

            validated.append(s)

        return validated


    # ------------------------------------------------------------------
    # Step 3: User selects which modules to include in the rc script
    # ------------------------------------------------------------------

    def _user_select(self, suggestions: list) -> list:
        """
        Prints the validated suggestion list and lets the operator
        choose which modules to include in the .rc script.
        """
        print("\n[+] Metasploit module suggestions:\n")

        for i, s in enumerate(suggestions, start=1):
            validated_tag = "[VALIDATED]" if s.get("validated") else "[UNVERIFIED]"
            print(f"  {i}. {validated_tag} Rank {s.get('rank')} — {s.get('cve_id')}")
            print(f"     Module : {s.get('msf_module') or 'None'}")
            print(f"     Target : {s.get('software')} {s.get('service')} port {s.get('port')}")
            print(f"     Reason : {s.get('reason')}")
            print(f"     Note   : {s.get('validation_note', '')}\n")

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
    # Step 4: Generate the .rc script
    # ------------------------------------------------------------------

    def _generate_rc_script(self, selected: list):
        """
        Writes a Metasploit resource script (.rc) for the selected modules.

        The operator runs it with:
            msfconsole -r {target}_modules.rc

        Each module block:
            use {module}
            set RHOSTS {target}
            set RPORT {port}
            set {any other options}
            run
        """
        safe_target = self.target.replace(".", "_")
        filename    = f"{safe_target}_modules.rc"

        lines = [
            "# xRECON generated Metasploit resource script",
            f"# Target: {self.target}",
            f"# Modules: {len(selected)}",
            "#",
            "# Run with: msfconsole -r " + filename,
            "# IMPORTANT: Only run against authorized targets.",
            "",
        ]

        for s in selected:
            msf_module = s.get("msf_module")

            if not msf_module:
                continue

            lines.append(f"# {s.get('cve_id')} — {s.get('reason')}")
            lines.append(f"# Validated: {s.get('validated')} — {s.get('validation_note', '')}")
            lines.append(f"use {msf_module}")

            # Write set options
            options = s.get("set_options", {})

            # Always ensure RHOSTS is set to our target
            if "RHOSTS" not in options:
                options["RHOSTS"] = self.target

            for option, value in options.items():
                lines.append(f"set {option} {value}")

            lines.append("run")
            lines.append("")   # blank line between modules

        try:
            with open(filename, "w") as f:
                f.write("\n".join(lines))
            print(f"\n[+] Resource script saved: {filename}")
            print(f"    Run with: msfconsole -r {filename}\n")
        except Exception as e:
            print(f"[!] Could not write .rc script: {e}")


    # ------------------------------------------------------------------
    # Export suggestions to JSON
    # ------------------------------------------------------------------

    def save_results(self, suggestions: list):
        """
        Saves the full suggestion list to JSON for reporting.
        """
        safe_target = self.target.replace(".", "_")
        filename    = f"{safe_target}_msf_suggestions.json"

        try:
            with open(filename, "w") as f:
                json.dump(suggestions, f, indent=2)
            print(f"[+] MSF suggestions saved to {filename}")
        except Exception as e:
            print(f"[!] Could not save suggestions: {e}")
