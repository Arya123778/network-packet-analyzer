"""Packet capture using Scapy, plus an optional demo traffic generator.

Capturing real traffic needs administrator/root rights (and Npcap on Windows).
Demo mode needs neither, so the dashboard can be tried safely anywhere.
"""

import random
import threading
import time

try:
    from scapy.all import (
        ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, IPv6, get_if_list,
    )
    SCAPY_AVAILABLE = True
except Exception:  # scapy missing or capture libraries unavailable
    SCAPY_AVAILABLE = False

PORT_NAMES = {
    20: "FTP", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 3389: "RDP",
}

ICMP_TYPES = {
    0: "Echo reply", 3: "Destination unreachable", 8: "Echo request", 11: "Time exceeded",
}


def _service_name(sport, dport):
    return PORT_NAMES.get(dport) or PORT_NAMES.get(sport)


def extract_packet_fields(pkt):
    """Turn a Scapy packet into a small, JSON-friendly summary dict."""
    fields = {
        "src": "-", "dst": "-", "sport": None, "dport": None,
        "protocol": "Other", "transport": None, "length": len(pkt),
        "ttl": None, "flags": None, "info": "",
    }

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        fields.update(src=arp.psrc, dst=arp.pdst, protocol="ARP")
        if arp.op == 1:
            fields["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            fields["info"] = f"{arp.psrc} is at {arp.hwsrc}"
        return fields

    label = "Other"
    if pkt.haslayer(IP):
        ip = pkt[IP]
        fields.update(src=ip.src, dst=ip.dst, ttl=ip.ttl)
        label = "IPv4"
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        fields.update(src=ip6.src, dst=ip6.dst, ttl=ip6.hlim)
        label = "IPv6"
    elif pkt.haslayer(Ether):
        eth = pkt[Ether]
        fields.update(src=eth.src, dst=eth.dst)
        label = "Ethernet"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = str(tcp.flags)
        fields.update(
            sport=tcp.sport, dport=tcp.dport, transport="TCP", flags=flags,
            protocol=_service_name(tcp.sport, tcp.dport) or "TCP",
        )
        fields["info"] = f"{tcp.sport} -> {tcp.dport} [{flags}] Len={len(tcp.payload)}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        fields.update(
            sport=udp.sport, dport=udp.dport, transport="UDP",
            protocol=_service_name(udp.sport, udp.dport) or "UDP",
        )
        fields["info"] = f"{udp.sport} -> {udp.dport} Len={len(udp.payload)}"
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
            kind = "Response" if pkt[DNS].qr else "Query"
            fields.update(protocol="DNS")
            fields["info"] = f"{kind} {qname.rstrip('.')}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        fields.update(protocol="ICMP", transport="ICMP")
        fields["info"] = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
    else:
        fields.update(protocol=label)
        fields["info"] = f"{label} packet"

    return fields


class PacketCapture:
    def __init__(self, store):
        self.store = store
        self._sniffer = None
        self._demo_thread = None
        self._demo_stop = threading.Event()
        self.running = False
        self.mode = "idle"  # idle | live | demo
        self.interface = None
        self.bpf_filter = None
        self.error = None

    # --------------------------------------------------------------- interfaces
    @staticmethod
    def list_interfaces():
        if not SCAPY_AVAILABLE:
            return []
        try:
            return list(get_if_list())
        except Exception:
            return []

    # ------------------------------------------------------------------ control
    def start(self, interface=None, bpf_filter=None, demo=False):
        if self.running:
            raise RuntimeError("Capture is already running.")
        self.error = None
        self.interface = interface or None
        self.bpf_filter = (bpf_filter or "").strip() or None

        if demo:
            self._start_demo()
            return

        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install -r backend/requirements.txt")

        sniffer = AsyncSniffer(
            iface=self.interface, filter=self.bpf_filter, prn=self._handle_packet, store=False,
        )
        try:
            sniffer.start()
            time.sleep(0.5)  # give the sniffer thread time to fail on bad permissions/filters
        except Exception as exc:
            raise RuntimeError(f"Could not start capture: {exc}") from exc

        thread_error = getattr(sniffer, "exception", None)
        if thread_error is not None or not getattr(sniffer, "running", True):
            self._safe_stop(sniffer)
            hint = " Run the server as administrator/root." if isinstance(thread_error, PermissionError) else ""
            raise RuntimeError(f"Capture failed: {thread_error or 'sniffer stopped'}.{hint}")

        self._sniffer = sniffer
        self.running = True
        self.mode = "live"

    def stop(self):
        if self._sniffer is not None:
            self._safe_stop(self._sniffer)
            self._sniffer = None
        if self._demo_thread is not None:
            self._demo_stop.set()
            self._demo_thread.join(timeout=2)
            self._demo_thread = None
        self.running = False
        self.mode = "idle"

    @staticmethod
    def _safe_stop(sniffer):
        try:
            sniffer.stop()
        except Exception:
            pass

    def status(self):
        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface,
            "filter": self.bpf_filter,
            "scapy_available": SCAPY_AVAILABLE,
            "error": self.error,
        }

    # ---------------------------------------------------------------- callbacks
    def _handle_packet(self, pkt):
        try:
            self.store.add(extract_packet_fields(pkt))
        except Exception as exc:  # never let one odd packet kill the sniffer
            self.error = f"Skipped a packet: {exc}"

    # --------------------------------------------------------------- demo traffic
    def _start_demo(self):
        self._demo_stop.clear()
        self._demo_thread = threading.Thread(target=self._demo_loop, daemon=True)
        self._demo_thread.start()
        self.running = True
        self.mode = "demo"

    def _demo_loop(self):
        local = ["192.168.1.10", "192.168.1.23", "192.168.1.42"]
        remote = ["142.250.77.14", "151.101.1.69", "104.18.32.7", "13.107.42.14", "93.184.216.34"]
        domains = ["example.com", "api.github.com", "cdn.jsdelivr.net", "mail.google.com", "pypi.org"]
        templates = [
            ("HTTPS", "TCP", 443, 40), ("HTTP", "TCP", 80, 8), ("DNS", "UDP", 53, 18),
            ("SSH", "TCP", 22, 4), ("ICMP", "ICMP", None, 5), ("ARP", None, None, 6),
            ("UDP", "UDP", 5353, 7), ("TCP", "TCP", 8080, 12),
        ]
        weights = [t[3] for t in templates]

        while not self._demo_stop.is_set():
            proto, transport, port, _ = random.choices(templates, weights)[0]
            outbound = random.random() < 0.55
            a, b = random.choice(local), random.choice(remote)
            src, dst = (a, b) if outbound else (b, a)
            sport = random.randint(32768, 60999)
            fields = {
                "src": src, "dst": dst, "sport": None, "dport": None, "protocol": proto,
                "transport": transport, "length": random.choice([60, 74, 98, 120, 590, 1514]),
                "ttl": random.choice([64, 117, 128]), "flags": None, "info": "",
            }
            if proto == "ARP":
                fields.update(src=a, dst=random.choice(local), ttl=None, length=42)
                fields["info"] = f"Who has {fields['dst']}? Tell {a}"
            elif proto == "ICMP":
                fields["info"] = random.choice(["Echo request", "Echo reply"])
            elif transport == "TCP":
                flags = random.choice(["S", "SA", "A", "PA", "FA"])
                fields.update(sport=sport if outbound else port, dport=port if outbound else sport, flags=flags)
                fields["info"] = f"{fields['sport']} -> {fields['dport']} [{flags}] Len={fields['length'] - 54}"
            else:
                fields.update(sport=sport if outbound else port, dport=port if outbound else sport)
                if proto == "DNS":
                    kind = "Query" if outbound else "Response"
                    fields["info"] = f"{kind} {random.choice(domains)}"
                else:
                    fields["info"] = f"{fields['sport']} -> {fields['dport']} Len={fields['length'] - 42}"
            self.store.add(fields)
            self._demo_stop.wait(random.uniform(0.02, 0.25))
