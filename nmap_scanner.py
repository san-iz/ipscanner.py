import argparse
import os
import platform
import nmap
from colorama import Fore, init
import time

# Initialize colorama
init(autoreset=True)

# Function to clear the screen and set the title
def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")
    if platform.system() == "Windows":
        os.system("title Nmap Scanner")

clear_screen()

print(f'''
{Fore.RED}
          ▄████  ██▀███   ▄▄▄       ▄▄▄▄
         ██▒ ▀█▒▓██ ▒ ██▒▒████▄    ▓█████▄
        ▒██░▄▄▄░▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒ ▄██
        ░▓█  ██▓▒██▀▀█▄  ░██▄▄▄▄██ ▒██░█▀
        ░▒▓███▀▒░██▓ ▒██▒ ▓█   ▓██▒░▓█  ▀█▓
         ░▒   ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▒▓███▀▒
          ░   ░   ░▒ ░ ▒░  ▒   ▒▒ ░▒░▒   ░
        ░ ░   ░   ░░   ░   ░   ▒    ░    ░
              ░    ░           ░  ░ ░
                                         ░{Fore.RESET}
''')

parser = argparse.ArgumentParser(description="Nmap scanner using python-nmap")
parser.add_argument('-r', '--range', type=str, required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
parser.add_argument('-o', '--output-file', type=str, help="Output file path")
parser.add_argument('-t', '--scan-type', type=str, choices=['syn', 'udp', 'os', 'top-ports'], required=True, help="Type of scan to run")
args = parser.parse_args()

def log_scan_result(ip, scan_result, output_file=None):
    info = f"----------\nIP: {ip}\nPorts:\n"
    if 'tcp' in scan_result:
        for port in scan_result['tcp']:
            service = scan_result['tcp'][port]['name']
            state = scan_result['tcp'][port]['state']
            info += f"Port {port}: {service} ({state})\n"
    if 'udp' in scan_result:
        for port in scan_result['udp']:
            service = scan_result['udp'][port]['name']
            state = scan_result['udp'][port]['state']
            info += f"Port {port}: {service} ({state})\n"
    if 'osclass' in scan_result:
        info += "OS Detection:\n"
        for osclass in scan_result['osclass']:
            info += f"OS Type: {osclass['type']}, Vendor: {osclass['vendor']}, OS Family: {osclass['osfamily']}, OS Generation: {osclass['osgen']}\n"
    info += "----------"
    print(info)
    if output_file:
        with open(output_file, "a+") as log:
            log.write(info + "\n")

def scan_network(ip_range, scan_type, output_file=None):
    nm = nmap.PortScanner()
    try:
        if scan_type == 'syn':
            nm.scan(hosts=ip_range, arguments='-sS -p 1-1024')
        elif scan_type == 'udp':
            nm.scan(hosts=ip_range, arguments='-sU -p 1-1024')
        elif scan_type == 'os':
            nm.scan(hosts=ip_range, arguments='-O')
        elif scan_type == 'top-ports':
            nm.scan(hosts=ip_range, arguments='--top-ports 100')
        else:
            raise ValueError("Unsupported scan type")

        for host in nm.all_hosts():
            scan_result = nm[host]
            log_scan_result(host, scan_result, output_file)

    except KeyboardInterrupt:
        print(Fore.RED + "Scan interrupted by user.")
        for host in nm.all_hosts():
            scan_result = nm[host]
            log_scan_result(host, scan_result, output_file)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

def display_progress(ip_range, scan_type):
    nm = nmap.PortScanner()
    host_list = [host.strip() for host in ip_range.split(',')]
    total_hosts = len(host_list)
    try:
        for i, host in enumerate(host_list):
            print(f"Scanning {host} ({i + 1}/{total_hosts})...")
            if scan_type == 'syn':
                nm.scan(hosts=host, arguments='-sS -p 1-1024')
            elif scan_type == 'udp':
                nm.scan(hosts=host, arguments='-sU -p 1-1024')
            elif scan_type == 'os':
                nm.scan(hosts=host, arguments='-O')
            elif scan_type == 'top-ports':
                nm.scan(hosts=host, arguments='--top-ports 100')
            else:
                raise ValueError("Unsupported scan type")
            scan_result = nm[host]
            log_scan_result(host, scan_result, args.output_file)
    except KeyboardInterrupt:
        print(Fore.RED + "Scan interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    display_progress(args.range, args.scan_type)
