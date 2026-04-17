#!/usr/bin/env python3

import xml.etree.ElementTree as ET


class NmapXMLParser:
    def __init__(self, xml_path: str):
        self.xml_path = xml_path

    # ------------------------------------------------------------
    # Parse entire XML file
    # ------------------------------------------------------------
    def parse(self):
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
        except Exception as e:
            print(f"[!] Failed to parse XML: {e}")
            return {"hosts": []}

        hosts = []

        for host_elem in root.findall("host"):
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                continue

            ip = addr_elem.get("addr")
            services = self._parse_services(host_elem)

            hosts.append({
                "ip": ip,
                "services": services
            })

        return {"hosts": hosts}

    # ------------------------------------------------------------
    # Parse all services for a host
    # ------------------------------------------------------------
    def _parse_services(self, host_elem):
        services = []

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            return services

        for port_elem in ports_elem.findall("port"):
            port_id = port_elem.get("portid")
            if not port_id:
                continue

            try:
                port = int(port_id)
            except ValueError:
                continue

            service_elem = port_elem.find("service")
            if service_elem is None:
                continue

            product, version = self._extract_service_info(service_elem)

            services.append({
                "port": port,
                "product": product,
                "version": version
            })

        return services

    # ------------------------------------------------------------
    # Extract product/version with fallback logic
    # ------------------------------------------------------------
    def _extract_service_info(self, service_elem):
        """
        Extracts product/version from <service> tag using robust fallback logic.
        Handles:
            - product=""
            - version=""
            - name=""
            - extrainfo=""
            - Samba/CUPS style versions in extrainfo
        """

        name = service_elem.get("name")
        product = service_elem.get("product")
        version = service_elem.get("version")
        extrainfo = service_elem.get("extrainfo")

        # -----------------------------
        # PRODUCT FALLBACKS
        # -----------------------------
        if not product:
            # If product missing, use service name
            product = name

        # Normalize product
        if product:
            product = product.strip()

        # -----------------------------
        # VERSION FALLBACKS
        # -----------------------------
        if version:
            version = version.strip()
        else:
            # Samba, CUPS, etc. often put version in extrainfo
            if extrainfo:
                # Extract first token that looks like a version
                tokens = extrainfo.split()
                if tokens:
                    version = tokens[0].strip()

        # If still no version, leave as None
        if version == "":
            version = None

        return product, version
