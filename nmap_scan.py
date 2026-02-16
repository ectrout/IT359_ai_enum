import subprocess


class NmapScan:
    def __init__(self, target):
        self.target = target
        self.command = ["nmap", "-Pn", "-sC", "-sV", target]
        self.stdout = None
        self.stderr = None
        self.returncode = None

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
