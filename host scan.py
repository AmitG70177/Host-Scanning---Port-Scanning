import socket
import ipaddress
import concurrent.futures

# Config
TIMEOUT = 1  # seconds
MAX_HOST_THREADS = 100
MAX_PORT_THREADS = 100


def get_user_input():
    network_input = input("Enter network CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        network = ipaddress.ip_network(network_input, strict=False)
    except ValueError:
        print("[!] Invalid network.")
        exit(1)

    port_input = input("Enter port range (e.g., 20-100): ").strip()
    try:
        start_port, end_port = map(int, port_input.split("-"))
        if not (1 <= start_port <= 65535 and start_port <= end_port):
            raise ValueError
        ports = list(range(start_port, end_port + 1))
    except ValueError:
        print("[!] Invalid port range.")
        exit(1)

    return network, ports


def is_host_alive(ip, ports):
    """Check if host is alive by trying TCP connect on first few ports"""
    for port in ports[:5]:  # try first 5 ports only
        try:
            with socket.create_connection((str(ip), port), timeout=TIMEOUT):
                print(f"[+] {ip} is alive (TCP connect on port {port})")
                return ip
        except:
            continue
    return None


def scan_port(ip, port):
    try:
        with socket.create_connection((str(ip), port), timeout=TIMEOUT):
            return port
    except:
        return None


def scan_host_ports(ip, ports):
    print(f"[~] Scanning ports on {ip}...")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PORT_THREADS) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print(f"[✓] {ip} has open ports: {sorted(open_ports)}")
    else:
        print(f"[-] No open ports found on {ip}")


def main():
    network, ports = get_user_input()
    all_hosts = list(network.hosts())
    live_hosts = []

    print(f"[~] Scanning {len(all_hosts)} hosts in {network} for liveness...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_HOST_THREADS) as executor:
        futures = [executor.submit(is_host_alive, ip, ports) for ip in all_hosts]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                live_hosts.append(result)

    if live_hosts:
        print(f"\n[✓] Found {len(live_hosts)} live host(s). Beginning port scan...\n")
        for host in live_hosts:
            scan_host_ports(host, ports)
    else:
        print("[~] No live hosts found.")


if __name__ == "__main__":
    main()
