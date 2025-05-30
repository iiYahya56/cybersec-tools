import socket
import threading
import struct
import textwrap
import argparse

# =========================
# Simple Port Scanner
# =========================
def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                print(f"[+] Port {port}/tcp is open")
    except Exception:
        pass

def port_scanner(host, ports, threads=100):
    print(f"Scanning {host} for ports: {min(ports)}-{max(ports)}")
    thread_list = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(host, port))
        t.start()
        thread_list.append(t)
        if len(thread_list) >= threads:
            for thr in thread_list:
                thr.join()
            thread_list = []
    # join any remaining threads
    for thr in thread_list:
        thr.join()

# =========================
# Simple Packet Sniffer
# =========================

def mac_addr(address_bytes):
    """Convert bytes to MAC address string"""
    return ':'.join(format(b, '02x') for b in address_bytes)

class PacketSniffer:
    def __init__(self, interface=None):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if interface:
            self.socket.bind((interface, 0))

    def run(self):
        print("Starting packet sniffer... Press Ctrl+C to stop.")
        try:
            while True:
                raw_data, addr = self.socket.recvfrom(65535)
                dest_mac, src_mac, proto = struct.unpack('!6s6sH', raw_data[:14])
                print(f"\nEthernet Frame: Src={mac_addr(src_mac)}, Dest={mac_addr(dest_mac)}, Proto={hex(proto)}")

                # IP packets (0x0800)
                if proto == 0x0800:
                    version_header_length = raw_data[14]
                    version = version_header_length >> 4
                    ihl = (version_header_length & 0xF) * 4
                    ttl, proto_num, src, target = struct.unpack('!8xBB2x4s4s', raw_data[14:34])
                    print(f"IPv{version} Packet: Src={socket.inet_ntoa(src)}, Dest={socket.inet_ntoa(target)}, TTL={ttl}, Proto={proto_num}")
        except KeyboardInterrupt:
            print("\nStopping sniffer.")
        except PermissionError:
            print("Error: requires root privileges to run packet sniffer.")

# =========================
# CLI Interface
# =========================

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner & Packet Sniffer")
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_scan = subparsers.add_parser('scan', help='Run port scanner')
    parser_scan.add_argument('host', help='Target hostname or IP')
    parser_scan.add_argument('--start', type=int, default=1, help='Start port (default 1)')
    parser_scan.add_argument('--end', type=int, default=1024, help='End port (default 1024)')
    parser_scan.add_argument('--threads', type=int, default=100, help='Number of threads')

    parser_sniff = subparsers.add_parser('sniff', help='Run packet sniffer')
    parser_sniff.add_argument('--iface', help='Network interface (e.g., eth0)')

    args = parser.parse_args()
    if args.command == 'scan':
        ports = range(args.start, args.end + 1)
        port_scanner(args.host, ports, args.threads)
    elif args.command == 'sniff':
        sniffer = PacketSniffer(args.iface)
        sniffer.run()

if __name__ == '__main__':
    main()
