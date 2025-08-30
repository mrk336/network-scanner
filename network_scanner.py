#!/usr/bin/env python3
"""
Enhanced Network Scanner Tool
Scans a host or subnet using Nmap, identifies devices by MAC address,
detects vulnerabilities (CVEs), and logs results to a CSV file.

Author: Mark Mallia
Date  : 2025-08-30
"""

from pathlib import Path
import csv
import sys

DEV_FILE = Path("dev.txt")

def ensure_dev_file():
    if not DEV_FILE.exists():
        with DEV_FILE.open("w") as f:
            f.write("# MAC Address    Device Name\n")
            f.write("00:11:22:33:44:55    Printer\n")
        print("[+] Created 'dev.txt' with sample data.")

def read_mac(mac_addr: str) -> str:
    mac_dict = {}
    try:
        with DEV_FILE.open() as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 2:
                    mac_dict[parts[0]] = parts[1]
    except Exception:
        return "Unknown"
    return mac_dict.get(mac_addr, "Unknown")

def extract_cves(script_output: dict) -> list:
    cves = []
    for output in script_output.values():
        lines = output.splitlines()
        for line in lines:
            if "CVE-" in line:
                cves.extend([word for word in line.split() if word.startswith("CVE-")])
    return list(set(cves))  # Remove duplicates

def run_scan(target: str):
    try:
        import nmap
    except ImportError as exc:
        print(f"[!] python-nmap not installed: {exc}")
        sys.exit(1)

    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, arguments="-sV --script vuln")
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")
        return {}

    results = {}
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', '')
        os_matches = scanner[host].get('osmatch', [])
        os_info = os_matches[0]['name'] if os_matches else "Unknown"
        devname = read_mac(mac)
        cve_list = []

        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                script_output = scanner[host][proto][port].get('script', {})
                cve_list.extend(extract_cves(script_output))

        results[host] = {
            "mac": mac,
            "os": os_info,
            "devname": devname,
            "cves": ", ".join(sorted(set(cve_list))) if cve_list else "None"
        }

    return results

def write_to_file(data, output_path: Path):
    with output_path.open("w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "MAC Address", "OS", "Device Name", "CVEs"])
        for ip, info in data.items():
            writer.writerow([ip, info["mac"], info["os"], info["devname"], info["cves"]])

def main():
    print("Welcome to the Enhanced Network Scanner Tool")
    print("Would you like to scan a single host or an entire subnet?")
    choice = input("Type 'host' or 'subnet': ").strip().lower()

    if choice == "host":
        target = input("Enter the IP address of the host: ").strip()
    elif choice == "subnet":
        target = input("Enter the subnet (e.g. 192.168.1.0/24): ").strip()
    else:
        print("[!] Invalid choice. Please restart and choose 'host' or 'subnet'.")
        sys.exit(1)

    output_file = input("Enter output filename (default: scan_results.csv): ").strip()
    if not output_file:
        output_file = "scan_results.csv"

    ensure_dev_file()

    print(f"[+] Scanning {target} for vulnerabilities...")
    scan_results = run_scan(target)
    write_to_file(scan_results, Path(output_file))
    print(f"[+] Scan complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()
