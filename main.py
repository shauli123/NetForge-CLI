import argparse
import cmd
import shlex
import sys
import readline
import psutil
import ipaddress
import src.core as core
import src.recon as recon
from src.ports_db import TCP_PORTS, UDP_PORTS
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.panel import Text
    
class NetForgeCLI(cmd.Cmd):
    prompt = 'NetForge > '
    console = Console()
    TOP_TCP_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 554, 3306, 3389, 8080, 8443]
    
    def __init__(self):
        super().__init__()
        self.current_subnet = core.get_local_subnet(conf.iface)
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind("set completion-query-items 0")
        
    def preloop(self):
        banner_text = Text()
        banner_text.append("   _  _     _   ___                    \n", style="bold cyan")
        banner_text.append("  | \| |___| |_| __|__  _ _ __ _ ___   \n", style="bold cyan")
        banner_text.append("  | .` / -_)  _| _/ _ \| '_/ _` / -_)  \n", style="bold cyan")
        banner_text.append("  |_|\_\___|\__|_|\___/|_| \__, \___|  \n", style="bold cyan")
        banner_text.append("                           |___/       \n", style="bold cyan")
        banner_text.append("─" * 40 + "\n", style="dim white")
        banner_text.append("Interactive Network Forge & Auditing Tool\n", style="italic white")
        banner_text.append("Version: ", style="dim white")
        banner_text.append("1.0.0 (Vanguard)\n", style="green")
        banner_text.append("Type 'help' or '?' to see available tools.", style="yellow")
        
        panel = Panel(banner_text, border_style="bold #333333", padding=(1, 4), expand=False)
        self.console.print("\n")
        self.console.print(panel)
        self.console.print("\n")   
        self.do_select_iface(None)

    def do_exit(self, arg):
        """Exit NetForge."""
        self.console.print("[bold magenta]Exiting NetForge. Goodbye![/bold magenta]")
        return True

    def do_arp_scan(self, arg):
        """Do a full ARP scan on current iface"""
        with self.console.status("[bold cyan]Scanning...") as status:
            results = recon.arp_scan(self.current_subnet)
        
        # set table
        table = Table(title="Scan Results", border_style="blue")
        table.add_column("Index", style="cyan", justify="center")
        table.add_column("IP Address", style="green")
        table.add_column("MAC Address", style="yellow")
        
        index = 1
        for res in results:
            table.add_row(str(index), res['ip'], res['mac'])
            index += 1
        self.console.print(table)

    def parse_ports(self, port_list):
        valid_ports = set()
        
        for item in port_list:
            item = str(item).strip()
            
            if '-' in item:
                try:
                    start, end = map(int, item.split('-'))
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                        valid_ports.update(range(start, end + 1))
                except ValueError:
                    continue
                    
            elif item.isnumeric():
                port = int(item)
                if 0 <= port <= 65535:
                    valid_ports.add(port)
                    
        return sorted(list(valid_ports))

    @property
    def tcp_scan_parser(self):
        parser = argparse.ArgumentParser(
            prog="tcp_scan", description="Scans for tcp open ports"
        )
        parser.add_argument("target", help="The target to scan")
        parser.add_argument('-p', '--ports', help="List of ports and ranges to scan (comma separated like 80,443,100-150,25)")
        return parser
    
    def do_tcp_scan(self, args):
        args_list = shlex.split(args)
        
        try:
            parsed_args = self.tcp_scan_parser.parse_args(args_list)
        except SystemExit:
            return
        
        ports = self.TOP_TCP_PORTS
        
        if parsed_args.ports:
            split_list = parsed_args.ports.split(',')
            ports = self.parse_ports(split_list)
        
        with self.console.status("[bold cyan]Scanning...") as status:
            results = recon.tcp_syn_port_scan(parsed_args.target, ports)
        
        table = Table(title="Scan Results - OPEN PORTS", border_style="green")
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Name", style="blue")
        table.add_column("Description", style="yellow")
        
        for port in results[True]:
            port_data = TCP_PORTS[port]
            try:
                table.add_row(str(port), port_data['name'], port_data['desc'])
            except:
                table.add_row(str(port), 'Unknown', '')
                

        self.console.print(table)
        self.console.print(f"\tScanned all {len(ports)}. {len(results[True])} ports were open, {len(results[False])} ports were close!", style='green')
        
    def help_tcp_scan(self):
        self.tcp_scan_parser.print_help()
        
    def _get_ipv4_address(self, addresses):
        for addr in addresses:
            if addr.family == 2:
                return addr.address, addr.netmask
        return None, None

    def do_select_iface(self, arg):
        """Select an active network interface from a list."""
        interfaces = psutil.net_if_addrs()
        self.interfaces_list = []
        
        table = Table(title="Available Network Interfaces", border_style="blue")
        table.add_column("Index", style="cyan", justify="center")
        table.add_column("Interface Name", style="green")
        table.add_column("IP Address", style="magenta")
        table.add_column("Subnet Mask", style="yellow")

        index = 1
        for iface_name, addresses in interfaces.items():
            ip, netmask = self._get_ipv4_address(addresses)
            if ip:
                table.add_row(str(index), iface_name, ip, netmask)
                self.interfaces_list.append({
                    "name": iface_name,
                    "ip": ip,
                    "netmask": netmask
                })
                index += 1

        if not self.interfaces_list:
            self.console.print("No active IPv4 interfaces found.", style="bold red")
            return

        self.console.print(table)
        
        try:
            choice = self.console.input("\n[bold yellow]Select interface index: [/bold yellow]")
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(self.interfaces_list):
                selected = self.interfaces_list[choice_idx]
                conf.iface = selected["name"]
                
                network = ipaddress.IPv4Network(f"{selected['ip']}/{selected['netmask']}", strict=False)
                clean_subnet = network.with_prefixlen
                
                self.console.print(f"\n[bold green]Successfully switched to: {selected['name']}[/bold green]")
                self.console.print(f"[bold green]Active Subnet: {clean_subnet}[/bold green]\n")
                
                self.current_subnet = clean_subnet
                
            else:
                self.console.print("Invalid index choice.", style="bold red")
        except ValueError:
            self.console.print("Please enter a valid number.", style="bold red")

if __name__ == '__main__':
    
    NetForgeCLI().cmdloop()