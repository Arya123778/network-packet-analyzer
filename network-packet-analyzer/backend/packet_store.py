"""In-memory storage for recent packet summaries plus running statistics."""

import threading
import time
from collections import Counter, deque

TIMELINE_SECONDS = 60


class PacketStore:
    def __init__(self, max_packets=2000):
        self._packets = deque(maxlen=max_packets)
        self._lock = threading.Lock()
        self._next_id = 1
        self._reset_counters()

    def _reset_counters(self):
        self.total_packets = 0
        self.total_bytes = 0
        self._proto_count = Counter()
        self._proto_bytes = Counter()
        self._src_packets = Counter()
        self._src_bytes = Counter()
        self._dst_packets = Counter()
        self._dst_bytes = Counter()
        self._buckets = {}  # epoch second -> [packets, bytes]

    # ------------------------------------------------------------------ writes
    def add(self, fields):
        """Store one packet summary (a dict from packet_capture) and update stats."""
        now = time.time()
        length = int(fields.get("length", 0))
        proto = fields.get("protocol", "Other")
        src = fields.get("src", "-")
        dst = fields.get("dst", "-")

        with self._lock:
            record = dict(fields)
            record["id"] = self._next_id
            record["timestamp"] = now
            record["time"] = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}"
            self._next_id += 1
            self._packets.append(record)

            self.total_packets += 1
            self.total_bytes += length
            self._proto_count[proto] += 1
            self._proto_bytes[proto] += length
            self._src_packets[src] += 1
            self._src_bytes[src] += length
            self._dst_packets[dst] += 1
            self._dst_bytes[dst] += length

            bucket = self._buckets.setdefault(int(now), [0, 0])
            bucket[0] += 1
            bucket[1] += length
            cutoff = int(now) - TIMELINE_SECONDS * 2
            for sec in [s for s in self._buckets if s < cutoff]:
                del self._buckets[sec]

    def clear(self):
        with self._lock:
            self._packets.clear()
            self._reset_counters()

    # ------------------------------------------------------------------- reads
    def get_packets(self, limit=200, protocol=None, search=None, after_id=0):
        """Return newest-first packet summaries, optionally filtered."""
        search = (search or "").strip().lower()
        with self._lock:
            packets = list(self._packets)

        result = []
        for pkt in reversed(packets):
            if pkt["id"] <= after_id:
                break
            if protocol and protocol != "all" and pkt["protocol"] != protocol:
                continue
            if search:
                haystack = " ".join(
                    str(pkt.get(k, "")) for k in ("src", "dst", "sport", "dport", "protocol", "info")
                ).lower()
                if search not in haystack:
                    continue
            result.append(pkt)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _top(packets, byte_counts, n=5):
        ranked = sorted(packets.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return [{"address": a, "packets": c, "bytes": byte_counts[a]} for a, c in ranked]

    def stats(self):
        now = int(time.time())
        with self._lock:
            timeline = []
            for sec in range(now - TIMELINE_SECONDS + 1, now + 1):
                pk, by = self._buckets.get(sec, (0, 0))
                timeline.append({"t": sec, "packets": pk, "bytes": by})

            recent = timeline[-5:]
            pps = sum(b["packets"] for b in recent) / len(recent)
            bps = sum(b["bytes"] for b in recent) / len(recent)

            total = self.total_packets or 1
            protocols = [
                {
                    "name": name,
                    "count": count,
                    "bytes": self._proto_bytes[name],
                    "percent": round(count * 100 / total, 1),
                }
                for name, count in self._proto_count.most_common()
            ]

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packets_per_second": round(pps, 1),
                "bytes_per_second": round(bps, 1),
                "protocols": protocols,
                "top_sources": self._top(self._src_packets, self._src_bytes),
                "top_destinations": self._top(self._dst_packets, self._dst_bytes),
                "timeline": timeline,
            }
