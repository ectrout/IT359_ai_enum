import subprocess

"""
nmap_scan.py

This tool is an object oriented Nmap execution. 
This class is not very modular and is specifically designed to feed Nmap data to Ollama LLMs
This is a part of a larger pen testing framework using ai

Author: Eric Trout
Project: IT-359 AI Pen Testing enumerator
"""
class NmapScan:
    def __init__(self, target):
        self.target = target
        self.command = ["nmap", "-Pn", "-sC", "-sV", "-O", target]
        self.stdout = None
        self.stderr = None
        self.returncode = None
        self.json_data = None; 

    def run(self):
        try:
            result = subprocess.run(
                self.command,
                capture_output=True,
                text=True,
                check=True
            )

            self.stdout = result.stdout
            self.stderr = result.stderr
            self.returncode = result.returncode

        except FileNotFoundError:
            print("Nmap not installed.")
        except subprocess.CalledProcessError as e:
            print("Scan failed.")
            self.stderr = e.stderr
        except Exception as e:
            print(f"Unexpected error: {e}")

    def get_output(self):
        return self.stdout

    def to_dict(self):
        return {
            "target": self.target,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr
        }
def convert_to_json(self): 
    try:
        self.json_data = json.dumps(self.to_dict(), indent=4)
    except Exception as e: 
        print(f"JSON conversion error: {e}")
def save_json(self, filenname=f"scan_results.json"):
    if self.json_data is None: 
        self.convert_to_json()
    try: 
        with open(filename, "w") as file: 
            file.write(self.json_data)
    except Exception as e: 
        print(f"File writing error: " {e}) 

def get_raw_output(self):
    return self.stdout 

def get_json_output(self): 
    if self.json_data is None: 
        self.convert_to_json() 
    return self.json_data

