"""netmapper: find the devices on YOUR network and the common ports they have open.

Pure Python, no admin rights needed. Only scan networks you own or have permission to scan.
CLI:  python3 netmapper.py            (auto-detects your subnet)
      python3 netmapper.py 192.168.1.0/24
Web:  python3 -m streamlit run app.py
"""
import errno
import ipaddress
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

# port -> (service name, risk, why it matters)
PORTS = {
    21: ("FTP", "high", "Sends passwords in plain text"),
    22: ("SSH", "medium", "Remote login. Fine if you set it up, risky with weak passwords"),
    23: ("Telnet", "high", "Unencrypted remote login. Should almost never be open"),
    25: ("SMTP", "medium", "Mail server"),
    53: ("DNS", "low", "Name lookups, normal on routers"),
    80: ("HTTP", "low", "Web page without encryption, often a router or camera admin page"),
    110: ("POP3", "medium", "Old unencrypted mail"),
    139: ("NetBIOS", "medium", "Old Windows file sharing"),
    143: ("IMAP", "medium", "Mail"),
    443: ("HTTPS", "low", "Encrypted web page"),
    445: ("SMB", "high", "Windows file sharing, a common attack target"),
    548: ("AFP", "medium", "Apple file sharing"),
    554: ("RTSP", "medium", "Camera video stream"),
    3389: ("RDP", "high", "Windows remote desktop, a common attack target"),
    5900: ("VNC", "high", "Remote screen control, often weakly protected"),
    8080: ("HTTP-alt", "low", "Alternate web page"),
    8443: ("HTTPS-alt", "low", "Alternate encrypted web page"),
}
MAX_HOSTS = 1024


def get_local_ip():
    """Find this machine's LAN IP. No packets are sent, connect() on UDP only picks a route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_subnet():
    """Guess the local subnet as a /24 around our own IP."""
    return str(ipaddress.ip_network(f"{get_local_ip()}/24", strict=False))


def parse_network(text):
    """Validate user input. Only private (home/office) ranges, and not huge ones."""
    net = ipaddress.ip_network(text.strip(), strict=False)
    if not net.is_private:
        raise ValueError("Only private networks (like 192.168.x.x or 10.x.x.x) are allowed.")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(f"Network too big ({net.num_addresses} addresses). Max is {MAX_HOSTS}.")
    return net


def check_port(ip, port, timeout=0.6):
    """Return 'open', 'closed' (host answered, port shut) or 'filtered' (no answer)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        code = s.connect_ex((ip, port))
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    return "filtered"


def scan_host(ip, ports=None, timeout=0.6):
    """Check ports on one host. Returns {'ip', 'alive', 'open_ports'}."""
    ports = list(ports or PORTS)
    open_ports, alive = [], False
    for port in ports:
        state = check_port(ip, port, timeout)
        if state == "open":
            open_ports.append(port)
            alive = True
        elif state == "closed":
            alive = True  # host answered with a refusal, so it exists
    return {"ip": ip, "alive": alive, "open_ports": open_ports}


def parse_arp(output):
    """Parse `arp -a` output into {ip: mac}. Works with macOS and Linux formats."""
    table = {}
    for line in output.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)
        if m:
            mac = ":".join(p.zfill(2) for p in m.group(2).lower().split(":"))
            table[m.group(1)] = mac
    return table


def read_arp_table():
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp(out)


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def worst_risk(open_ports):
    order = {"low": 1, "medium": 2, "high": 3}
    risks = [PORTS[p][1] for p in open_ports if p in PORTS]
    return max(risks, key=order.get) if risks else "none"


def scan_network(cidr, timeout=0.6, workers=100):
    """Scan every host in cidr. Returns a list of device dicts, sorted by IP."""
    net = parse_network(cidr)
    ips = [str(ip) for ip in net.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda ip: scan_host(ip, timeout=timeout), ips))
    arp = read_arp_table()  # hosts that ignore connections still answer ARP
    devices = []
    for r in results:
        mac = arp.get(r["ip"], "")
        if not (r["alive"] or mac):
            continue
        devices.append({
            "ip": r["ip"],
            "hostname": get_hostname(r["ip"]),
            "mac": mac,
            "open_ports": r["open_ports"],
            "services": ", ".join(f"{p}/{PORTS[p][0]}" for p in r["open_ports"]),
            "risk": worst_risk(r["open_ports"]),
        })
    # TODO (you): look up the MAC vendor (first 3 bytes) so "a4:83:e7" becomes "Apple"
    # TODO (you): grab banners from open ports to guess service versions
    # TODO (you): save each scan to a JSON file and show what changed since last time
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def main():
    cidr = sys.argv[1] if len(sys.argv) > 1 else default_subnet()
    print(f"Scanning {cidr} ... (only scan networks you own)")
    for d in scan_network(cidr):
        print(f"{d['ip']:15} {d['mac']:17} {d['hostname'][:28]:28} risk={d['risk']:6} {d['services']}")


if __name__ == "__main__":
    main()
