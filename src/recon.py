from scapy.all import *
def arp_scan(subnet: str):
    """scans the subnet with arp

    :param subnet: str subnet (scapy format)
    :type subnet: str
    :return: list of hosts (dicts {ip, mac})
    :rtype: list
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=3, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received[ARP].psrc,
            "mac": received[ARP].hwsrc,
        })

    return hosts

def tcp_syn_port_scan(target: str, ports: list, verbose = False) -> dict[bool,list[int]]:
    """runs a tcp port scan

    :param target: target ip
    :type target: str
    :param ports: port list
    :type ports: list
    :param verbose: to print logs? (default = False)
    :type verbose: bool
    :return: Open ports = True, Close = False
    :rtype: dict[bool,list[int]]
    """
    results = {True: [], False: []}
    for port in ports:
        if (verbose):
            print(f"Scanning port {port}...")
        try:
            ans = sr1(IP(dst=target) / TCP(dport=port), verbose = 0, timeout = 3)
            if ans and str(ans[TCP].flags) == 'RA':
                results[False].append(port)
            else:
                results[True].append(port)
        except:
            results[False].append(port)
    
    return results
