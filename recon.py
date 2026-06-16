from scapy.all import *
def arp_scan(subnet: str):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=3, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received[ARP].psrc,
            "mac": received[ARP].hwsrc,
        })

    return hosts
