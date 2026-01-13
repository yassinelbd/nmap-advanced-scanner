import nmap
import schedule
import time
from datetime import datetime

def scan_services(target):
    print(f"\n[+] Service/Version scan for {target} at {datetime.now()}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments="-sV -T4 --script vulners")

    for host in scanner.all_hosts():
        print(f"\nHost : {host} ({scanner[host].hostname()})")
        print(f"State : {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"Protocol : {proto}")
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                info = scanner[host][proto][port]
                print(f"  {port}/{proto}\tState: {info['state']}\tService: {info.get('name', '')} "
                      f"{info.get('product','')} {info.get('version','')}")

def scan_os(target):
    print(f"\n[+] OS scan for {target} at {datetime.now()}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments="-O")

    for host in scanner.all_hosts():
        print(f"\nHost : {host}")
        if 'osmatch' in scanner[host]:
            for os in scanner[host]['osmatch']:
                print(f"  Possible OS: {os['name']} (Accuracy {os['accuracy']}%)")
        else:
            print("  No OS detected")

def full_scan(target):
    scan_services(target)
    scan_os(target)
    
    filename = f"scan_report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        f.write(f"Scan for {target} at {datetime.now()}\n")
    print(f"[+] Scan results saved to {filename}")


def schedule_scan(target, minutes):
    schedule.every(minutes).minutes.do(full_scan, target=target)
    print(f"\n[+] Scheduled scan every {minutes} minutes for {target}\n")



if __name__ == "__main__":
    print("================ NMAP ADVANCED SCANNER ================")
    target = input("Enter target IP: ")

    print("\nChoose mode:")
    print("1) Full scan (services + OS + vulns)")
    print("2) Only services & vulnerabilities")
    print("3) Only OS scan")
    print("4) Schedule repeated scan")
    choice = input("Your choice: ")

    if choice == "1":
        full_scan(target)

    elif choice == "2":
        scan_services(target)

    elif choice == "3":
        scan_os(target)

    elif choice == "4":
        minutes = int(input("Repeat every (minutes): "))
        schedule_scan(target, minutes)

    else:
        print("[!] Invalid choice")
