import argparse
import os
import platform
import time
import requests
import nmap
from threading import Thread
from colorama import Fore

# Function to clear the screen and set the title
def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")
    os.system("title IP Scanner" if platform.system() == "Windows" else "")

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

parser = argparse.ArgumentParser(description="IP scanner")
parser.add_argument('-r', '--range', type=str, required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
parser.add_argument('-o', '--output-file', type=str, help="Output file path")
args = parser.parse_args()

def scan_ip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')  # Scan ports from 1 to 1024
    return nm[ip]

def log_scan_result(ip, scan_result, output_file=None):
    info = f"----------\nIP: {ip}\nPorts:\n"
    for port in scan_result['tcp']:
        service = scan_result['tcp'][port]['name']
        state = scan_result['tcp'][port]['state']
        info += f"Port {port}: {service} ({state})\n"
    info += "----------"
    print(info)
    if output_file:
        with open(output_file, "a+") as log:
            log.write(info + "\n")

def scan_network(ip_range, output_file):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-p 1-1024')
    for host in nm.all_hosts():
        scan_result = nm[host]
        log_scan_result(host, scan_result, output_file)

if __name__ == "__main__":
    scan_network(args.range, args.output_file)
