import subprocess
import json
from ftplib import FTP

"""
service_enum.py

Targeted service enumeration dispatcher for xRECON.
Receives a parsed list of {port, service, reason} dicts from Ollama,
runs the appropriate Kali enumeration tools, and returns a structured
findings dict for re-ingestion by the LLM.

Author: Eric Trout / Jake Cirks
Project: IT-359 xRECON AI Pen Testing Framework
"""


class ServiceEnumerator:

    def __init__(self, target: str, config: dict):
        self.target  = target
        self.config  = config
        self.timeout = config.get("timeout", 60)


    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def enumerate(self, port_list: list) -> dict:
        findings = []

        for item in port_list:
            port    = item.get("port")
            service = item.get("service", "")
            reason  = item.get("reason", "")

            print(f"[+] Enumerating port {port} ({service}) — {reason}")

            try:
                result = self._dispatch(port, service)
            except Exception as e:
                result = {"tool": None, "output": None, "error": str(e)}

            findings.append({
                "port":    port,
                "service": service,
                "reason":  reason,
                "tool":    result.get("tool"),
                "output":  result.get("output"),
                "error":   result.get("error")
            })

        return {
            "target":   self.target,
            "findings": findings
        }


    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _dispatch(self, port: int, service: str) -> dict:
        normalized = service.lower().split("-")[0]

        handlers = {
            "http":      self._enum_http,
            "https":     self._enum_https,
            "smb":       self._enum_smb,
            "microsoft": self._enum_smb,   # port 445 often labeled "microsoft-ds"
            "ftp":       self._enum_ftp,
            "ssh":       self._enum_ssh,
            "smtp":      self._enum_smtp,
        }

        handler = handlers.get(normalized)

        if handler:
            return handler(port)

        print(f"[!] No handler for '{service}', running nmap -sV fallback")
        return self._run(
            ["nmap", "-sV", "-p", str(port), self.target],
            "nmap-fallback"
        )


    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _enum_http(self, port: int) -> dict:
        url = f"http://{self.target}:{port}"

        # 1. Response headers
        headers_result = self._run(["curl", "-I", "--max-time", "10", url], "curl")
        headers_out = headers_result.get("output") or headers_result.get("error", "")

        # 2. Directory busting
        if self.config.get("gobuster", True):
            wordlist = self.config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            gobuster_result = self._run(
                ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error"],
                "gobuster"
            )
            gobuster_out = gobuster_result.get("output") or gobuster_result.get("error", "")
        else:
            gobuster_out = "gobuster disabled in config"

        # 3. Nikto
        if self.config.get("nikto", True):
            nikto_result = self._run(["nikto", "-h", url, "-nointeractive"], "nikto")
            nikto_out = nikto_result.get("output") or nikto_result.get("error", "")
        else:
            nikto_out = "nikto disabled in config"

        output = (
            f"--- HEADERS ---\n{headers_out}\n"
            f"--- GOBUSTER ---\n{gobuster_out}\n"
            f"--- NIKTO ---\n{nikto_out}"
        )
        return {"tool": "curl+gobuster+nikto", "output": output, "error": None}


    def _enum_https(self, port: int) -> dict:
        url = f"https://{self.target}:{port}"

        headers_result = self._run(["curl", "-I", "-k", "--max-time", "10", url], "curl")
        headers_out = headers_result.get("output") or headers_result.get("error", "")

        tls_result = self._run(["sslscan", "--no-colour", f"{self.target}:{port}"], "sslscan")
        tls_out = tls_result.get("output") or tls_result.get("error", "")

        if self.config.get("gobuster", True):
            wordlist = self.config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            gobuster_result = self._run(
                ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error", "-k"],
                "gobuster"
            )
            gobuster_out = gobuster_result.get("output") or gobuster_result.get("error", "")
        else:
            gobuster_out = "gobuster disabled in config"

        output = (
            f"--- HEADERS ---\n{headers_out}\n"
            f"--- TLS SCAN ---\n{tls_out}\n"
            f"--- GOBUSTER ---\n{gobuster_out}"
        )
        return {"tool": "curl+sslscan+gobuster", "output": output, "error": None}


    def _enum_smb(self, port: int) -> dict:
        enum4_result = self._run(["enum4linux", "-a", self.target], "enum4linux")
        enum4_out = enum4_result.get("output") or enum4_result.get("error", "")

        smb_result = self._run(["smbclient", "-L", f"//{self.target}/", "-N"], "smbclient")
        smb_out = smb_result.get("output") or smb_result.get("error", "")

        nmap_result = self._run(
            ["nmap", "--script", "smb-vuln*", "-p", str(port), self.target],
            "nmap-smb"
        )
        nmap_out = nmap_result.get("output") or nmap_result.get("error", "")

        output = (
            f"--- ENUM4LINUX ---\n{enum4_out}\n"
            f"--- SMBCLIENT NULL SESSION ---\n{smb_out}\n"
            f"--- NMAP SMB VULN SCRIPTS ---\n{nmap_out}"
        )
        return {"tool": "enum4linux+smbclient+nmap", "output": output, "error": None}


    def _enum_ftp(self, port: int) -> dict:
        output_parts = []

        banner_result = self._run(
            ["nmap", "-sV", "-p", str(port), "--script", "ftp-anon,ftp-banner", self.target],
            "nmap-ftp"
        )
        output_parts.append(f"--- BANNER / NMAP ---\n{banner_result.get('output') or banner_result.get('error', '')}")

        try:
            ftp = FTP()
            ftp.connect(self.target, port, timeout=10)
            banner = ftp.getwelcome()
            ftp.login()
            files = ftp.nlst()
            ftp.quit()
            output_parts.append(f"--- ANONYMOUS LOGIN SUCCEEDED ---\nBanner: {banner}\nFiles: {files}")
        except Exception as e:
            output_parts.append(f"--- ANONYMOUS LOGIN FAILED ---\n{str(e)}")

        return {"tool": "nmap-ftp+ftplib", "output": "\n".join(output_parts), "error": None}


    def _enum_ssh(self, port: int) -> dict:
        banner_result = self._run(
            ["nmap", "-sV", "-p", str(port), "--script", "ssh2-enum-algos,banner", self.target],
            "nmap-ssh"
        )
        banner_out = banner_result.get("output") or banner_result.get("error", "")

        ssh_result = self._run(
            ["ssh", "-o", "ConnectTimeout=5",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    f"{self.target}", "-p", str(port)],
            "ssh-banner"
        )
        ssh_out = ssh_result.get("output") or ssh_result.get("error", "")

        output = (
            f"--- NMAP SSH SCRIPTS ---\n{banner_out}\n"
            f"--- SSH BANNER GRAB ---\n{ssh_out}"
        )
        return {"tool": "nmap-ssh+ssh-banner", "output": output, "error": None}


    def _enum_smtp(self, port: int) -> dict:
        nmap_result = self._run(
            ["nmap", "-p", str(port), "--script", "smtp-enum-users,smtp-commands,smtp-vuln*", self.target],
            "nmap-smtp"
        )
        nmap_out = nmap_result.get("output") or nmap_result.get("error", "")

        vrfy_output = []
        users_to_probe = ["root", "admin", "administrator", "mail", "postmaster", "test"]

        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, port))
            banner = sock.recv(1024).decode(errors="ignore")
            vrfy_output.append(f"Banner: {banner.strip()}")

            for user in users_to_probe:
                sock.send(f"VRFY {user}\r\n".encode())
                response = sock.recv(1024).decode(errors="ignore").strip()
                vrfy_output.append(f"VRFY {user}: {response}")

            sock.send(b"QUIT\r\n")
            sock.close()
        except Exception as e:
            vrfy_output.append(f"Raw socket error: {str(e)}")

        output = (
            f"--- NMAP SMTP SCRIPTS ---\n{nmap_out}\n"
            f"--- VRFY USER PROBE ---\n" + "\n".join(vrfy_output)
        )
        return {"tool": "nmap-smtp+vrfy", "output": output, "error": None}


    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _run(self, cmd: list, tool_name: str) -> dict:
        """
        Shared subprocess wrapper. Every handler calls this so exception
        handling only needs to exist in one place.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return {"tool": tool_name, "output": result.stdout, "error": None}

        except FileNotFoundError:
            return {"tool": tool_name, "output": None, "error": f"{tool_name} not installed"}
        except subprocess.TimeoutExpired:
            return {"tool": tool_name, "output": None, "error": f"{tool_name} timed out"}
        except subprocess.CalledProcessError as e:
            return {"tool": tool_name, "output": None, "error": e.stderr}
        except Exception as e:
            return {"tool": tool_name, "output": None, "error": str(e)}
