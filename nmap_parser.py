import xml.etree.ElementTree as ET
from typing import List, Dict, Any


class NmapXMLParser:
    def __init__(self, xml_path: str):
        self.xml_path = xml_path

    def parse(self) -> Dict[str, Any]:
        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        hosts = []
        for host in root.findall("host"):
            addresses = [
                addr.get("addr")
                for addr in host.findall("address")
                if addr.get("addrtype") in ("ipv4", "ipv6")
            ]

            ports_data = []
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    portid = int(port.get("portid"))
                    protocol = port.get("protocol")

                    state_el = port.find("state")
                    state = state_el.get("state") if state_el is not None else None

                    service_el = port.find("service")
                    service = service_el.get("name") if service_el is not None else None
                    product = service_el.get("product") if service_el is not None else None
                    version = service_el.get("version") if service_el is not None else None
                    extrainfo = service_el.get("extrainfo") if service_el is not None else None

                    scripts = []
                    for script in port.findall("script"):
                        scripts.append({
                            "id": script.get("id"),
                            "output": script.get("output")
                        })

                    ports_data.append({
                        "port": portid,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "scripts": scripts,
                    })

            hosts.append({
                "addresses": addresses,
                "ports": ports_data,
            })

        return {"hosts": hosts}
