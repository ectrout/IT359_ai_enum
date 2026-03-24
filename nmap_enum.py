# File: nmap_enum.py  
# Purpose: TARGETED enumeration after initial scan
class NmapEnumerator:
    def __init__(self, target):
        self.target = target
    
    def enumerate_http(self, port):
        # Run ONLY HTTP scripts on ONLY HTTP port
        cmd = ["nmap", "-p", str(port), "--script", "http-enum,http-headers", self.target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def enumerate_smb(self, port):
        # Run ONLY SMB scripts on ONLY SMB port
        cmd = ["nmap", "-p", str(port), "--script", "smb-enum-shares,smb-os-discovery", self.target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
