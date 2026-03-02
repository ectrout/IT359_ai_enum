import requests
import subprocess
from ftplib import FTP
import ssl
import socket



class Tester:
    def __init__(self, target):
        self.target = target

    def run_test(self, test_name):
        #Small Json collection of tests, can add as methods are developed. 
        tests = {
            "http_title": self.http_title,
            "smb_null_session": self.smb_null_session,
            "ftp_anonymous": self.ftp_anonymous,
            "tls_version": self.tls_version
        }

        if test_name not in tests:
            return f"[!] Error Unknown Test: {test_name}"
        return tests[test_name]()
    
    def http_title(self):
        try:
            r = requests.get(f"http://{self.target}", timeout=5)
            if "<title>" in r.text.lower():
                start = r.text.lower().find("<title>") + 7
                end = r.text.lower().find("<title>") 
                return f"[HTTP] Title: {r.text[start:end]}"    
            return "[HTTP] No Title found."
        except Exception as e:
            return f"[HTTP] Error: {e}"
        
    def smb_null(self):
        try:
            result = subprocess.run(
                ["smbclient", "-L", f"//{self.target}/","-N"],
                capture_output = True, text=True
            )
            return result.stdout
        except Exception as e:
            return f"[SMB] Error: {e}"
        
    def ftp_anonymous(self):
        try:
            ftp = FTP(self.target, timeout =5)
            ftp.login()         #Anonymous is default login attempt
            files = ftp.nlst()
            ftp.quit()
            return f"[FTP] Anonymous login allowed. Files retrieved: {files}"
        except Exception as e:
            return f"[FTP] Anonymous login failed: {e}"
        
    def tls_version(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return f"[TLS] Version: {ssock.version()}"
        except Exception as e:
            return f"[TLS] Error: {e}"




