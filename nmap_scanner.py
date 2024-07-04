import argparse
import os
import platform
import nmap
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor

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
parser.add_argument('-t', '--scan-type', type=str, choices=[
    'syn', 'udp', 'os', 'top-ports', 'version', 'ping', 'all'], required=True, help="Type of scan to run")
parser.add_argument('-w', '--workers', type=int, default=10, help="Number of worker threads (default is 10)")
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
    if 'hostscript' in scan_result:
        info += "Host Scripts:\n"
        for script in scan_result['hostscript']:
            info += f"Script ID: {script['id']}, Output: {script['output']}\n"
    info += "----------"
    print(info)
    if output_file:
        with open(output_file, "a+") as log:
            log.write(info + "\n")

def scan_host(nm, ip, scan_type, output_file):
    if scan_type == 'syn':
        nm.scan(hosts=ip, arguments='-sS -p 1-1024')
    elif scan_type == 'udp':
        nm.scan(hosts=ip, arguments='-sU -p 1-1024')
    elif scan_type == 'os':
        nm.scan(hosts=ip, arguments='-O')
    elif scan_type == 'top-ports':
        nm.scan(hosts=ip, arguments='--top-ports 100')
    elif scan_type == 'version':
        nm.scan(hosts=ip, arguments='-sV')
    elif scan_type == 'ping':
        nm.scan(hosts=ip, arguments='-sn')
    elif scan_type == 'all':
        nm.scan(hosts=ip, arguments='-A')
    else:
        raise ValueError("Unsupported scan type")

    scan_result = nm[ip]
    log_scan_result(ip, scan_result, output_file)

def scan_network(ip_range, scan_type, output_file=None, workers=10):
    nm = nmap.PortScanner()
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            nm.scan(hosts=ip_range, arguments='-sn')  # Initial ping scan to discover hosts
            for ip in nm.all_hosts():
                executor.submit(scan_host, nm, ip, scan_type, output_file)
    except KeyboardInterrupt:
        print(Fore.RED + "Scan interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    scan_network(args.range, args.scan_type, args.output_file, args.workers)
