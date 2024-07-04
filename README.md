Install Required Libraries:
pip install python-nmap
pip install python-nmap colorama
Explanation:
Nmap Scanning: The script uses the nmap library to scan a specified range of IP addresses (-r argument). It scans ports from 1 to 1024 on each IP in the range.
Logging Results: The results of each scan are printed to the console and optionally logged to a file (-o argument).
Command-Line Arguments: The script uses command-line arguments to specify the IP range to scan and the output file for logging results.
Usage:
Run the script with the desired IP range and optional output file:
"python scanner.py -r 192.168.1.0/24 -o scan_results.txt"
This script will automatically scan the provided IP range and log the results. Make sure you have the necessary permissions to scan the target network to avoid legal and ethical issues.
