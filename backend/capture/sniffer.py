"""
sniffer.py — Packet Capture & Flow-Based Feature Extraction
Architecture: Sniffer Thread → Queue → Feature Extraction Worker
"""

import time
import threading
import csv
import os
from queue import Queue
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import backend.analysis.logger as logger
from backend.detection import rules

# ── Shared state ──────────────────────────────────────────────────────────────
packet_queue: Queue = Queue(maxsize=5000)

# Flow store: key = (src_ip, dst_ip, src_port, dst_port, proto)
# value = {start_time, last_time, pkt_count, byte_count, iats: []}
_flow_lock = threading.Lock()
_flows: dict = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "pkt_count": 0,
    "byte_count": 0,
    "iats": [],          # inter-arrival times in ms
})

# Completed windows of aggregated features fed to the detector
feature_windows: list = []           # list of dicts
feature_windows_lock = threading.Lock()

# ── Constants ─────────────────────────────────────────────────────────────────
WINDOW_SECONDS   = 5   # aggregate flows every 5 s
TRAFFIC_CSV_PATH = os.path.join("data", "traffic.csv")

_CSV_HEADERS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
    "pkt_count", "byte_count", "duration_s",
    "avg_pkt_size", "avg_iat_ms", "max_iat_ms",
]


def _get_flow_key(pkt):
    """Return a canonical 5-tuple key or None for non-IP packets."""
    if IP not in pkt:
        return None
    proto_num = pkt[IP].proto
    src_port = dst_port = 0
    if TCP in pkt:
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        proto_name = "TCP"
    elif UDP in pkt:
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        proto_name = "UDP"
    elif ICMP in pkt:
        proto_name = "ICMP"
    else:
        proto_name = str(proto_num)
    return (pkt[IP].src, pkt[IP].dst, src_port, dst_port, proto_name)


def _packet_callback(pkt):
    """Called by Scapy for every captured packet — must be fast."""
    if not packet_queue.full():
        packet_queue.put_nowait(pkt)


# ── Feature extraction worker ─────────────────────────────────────────────────
def _feature_worker():
    """Drains the queue, updates flows, and emits feature windows."""
    global feature_windows

    last_emit = time.time()

    while True:
        # Drain everything currently in the queue
        while not packet_queue.empty():
            try:
                pkt = packet_queue.get_nowait()
            except Exception:
                break

            key = _get_flow_key(pkt)
            if key is None:
                continue

            now_ms = time.time() * 1000
            pkt_len = len(pkt)

            with _flow_lock:
                flow = _flows[key]
                if flow["start_time"] is None:
                    flow["start_time"] = now_ms
                else:
                    flow["iats"].append(now_ms - flow["last_time"])
                flow["last_time"] = now_ms
                flow["pkt_count"] += 1
                flow["byte_count"] += pkt_len

            # Rule-based detection
            packet_data = {
                'src_ip': key[0],
                'dst_ip': key[1],
                'src_port': key[2],
                'dst_port': key[3],
                'proto': key[4],
                'timestamp': now_ms / 1000
            }
            rules.rule_detector.process_packet(packet_data)

        # Every WINDOW_SECONDS, snapshot flows → feature vector
        now = time.time()
        if now - last_emit >= WINDOW_SECONDS:
            last_emit = now
            _emit_window(now)

        time.sleep(0.05)   # 50 ms sleep to avoid busy-waiting


def _emit_window(timestamp: float):
    """Snapshot current flows into a feature window and reset."""
    rows = []
    with _flow_lock:
        for key, flow in list(_flows.items()):
            if flow["pkt_count"] == 0:
                continue
            dur = (flow["last_time"] - flow["start_time"]) / 1000.0 if flow["start_time"] else 0.0
            iats = flow["iats"] or [0]
            avg_iat = sum(iats) / len(iats)
            max_iat = max(iats)
            avg_pkt = flow["byte_count"] / flow["pkt_count"]

            row = {
                "timestamp":    timestamp,
                "src_ip":       key[0],
                "dst_ip":       key[1],
                "src_port":     key[2],
                "dst_port":     key[3],
                "proto":        key[4],
                "flow_key":     f"{key[0]}:{key[2]} -> {key[1]}:{key[3]} ({key[4]})", # easy backend identifier
                "pkt_count":    flow["pkt_count"],
                "byte_count":   flow["byte_count"],
                "duration_s":   round(dur, 4),
                "avg_pkt_size": round(avg_pkt, 2),
                "avg_iat_ms":   round(avg_iat, 2),
                "max_iat_ms":   round(max_iat, 2),
            }
            rows.append(row)

        # Reset flows for next window
        _flows.clear()

    if not rows:
        return

    # Save to feature_windows (keep last 500)
    with feature_windows_lock:
        feature_windows.extend(rows)
        if len(feature_windows) > 500:
            del feature_windows[:-500]

    # Persist to CSV
    _write_csv(rows)


def _write_csv(rows: list):
    """Append feature rows to traffic.csv."""
    os.makedirs("data", exist_ok=True)
    file_exists = os.path.isfile(TRAFFIC_CSV_PATH)
    try:
        with open(TRAFFIC_CSV_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_HEADERS)
            if not file_exists:
                writer.writeheader()
            for row in rows:
                writer.writerow({h: row.get(h, "") for h in _CSV_HEADERS})
    except Exception as e:
        logger.log_system(f"CSV write error: {e}")

_is_running = False

# ── Public API ────────────────────────────────────────────────────────────────
def start(interface=None):
    """
    Start the sniffer thread and feature-extraction worker thread.
    Can be instantiated from API endpoints.
    """
    global _is_running
    if _is_running:
        return
    _is_running = True

    # Feature extraction worker (daemon — dies with main process)
    worker = threading.Thread(target=_feature_worker, daemon=True, name="FeatureWorker")
    worker.start()

    # Scapy sniff in its own thread so it doesn't block Flask
    def _sniff():
        sniff(
            iface=interface,
            prn=_packet_callback,
            store=False,
            filter="ip",       # only IP traffic
        )

    sniffer = threading.Thread(target=_sniff, daemon=True, name="SnifferThread")
    sniffer.start()

    logger.log_system("Packet capture and feature worker started.")
