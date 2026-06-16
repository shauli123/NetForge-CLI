import psutil
import ipaddress
from scapy.all import *
import requests

def get_local_subnet(iface):
    target_ip = iface
    
    interfaces = psutil.net_if_addrs()
    
    for iface_name, addresses in interfaces.items():
        for addr in addresses:
            if addr.family == 2:
                if addr.address == target_ip:
                    netmask = addr.netmask
                    network = ipaddress.IPv4Network(f"{target_ip}/{netmask}", strict=False)
                    return network.with_prefixlen

    return f"{target_ip}/24"

def get_port_data_online(port: int, protocol: str = "tcp") -> dict:
    """get port data online from nmap files online

    :param port: the port number
    :type port: int
    :param protocol: the protocol at transport layer, defaults to "tcp"
    :type protocol: str, optional
    :return: dict of (name, description)
    :rtype: dict
    """
    protocol = protocol.lower()
    target_match = f"{port}/{protocol}"
    url = "https://svn.nmap.org/nmap/nmap-services"
    
    result = {
        "name": "unknown",
        "description": "Unrecognized or custom network service"
    }
    
    try:
        response = requests.get(url, timeout=5.0)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                if parts[1] == target_match:
                    result["name"] = parts[0]
                    
                    if "#" in line:
                        description = line.split("#", 1)[1].strip()
                        if description:
                            result["description"] = description
                    else:
                        result["description"] = f"Standard {parts[0].upper()} service"
                    
                    return result
    except Exception as e:
        result["description"] = f"Error fetching online database: {str(e)}"
        
    return result