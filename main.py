import cmd
import sys
import readline
import psutil
import ipaddress
import core
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.panel import Text

class NetForgeCLI(cmd.Cmd):
    prompt = 'NetForge > '
    console = Console()
    
    def __init__(self):
        super().__init__()
        self.target = None
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
            
    def do_set_target(self, arg):
        """Set the global target IP. Usage: set_target <IP>"""
        if not arg:
            self.console.print("[-] Please provide a valid IP address.", style="bold red")
            return
        self.target = arg
        self.console.print(f"[+] Target successfully set to: [bold green]{self.target}[/bold green]")

    def do_status(self, arg):
        """Show current configuration status."""
        if self.target:
            self.console.print(f"[+] Current Target: [bold cyan]{self.target}[/bold cyan]")
        else:
            self.console.print("[-] No target set. Use [bold yellow]set_target[/bold yellow] first.", style="red")

    def do_exit(self, arg):
        """Exit NetForge."""
        self.console.print("[bold magenta]Exiting NetForge. Goodbye![/bold magenta]")
        return True

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