import psutil
import ipaddress
from scapy.all import *

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
