"""
Network Traffic Capture and PCAP parsing module using Scapy.
Reconstructs bidirectional session flows and extracts encrypted metadata features
strictly without payload decryption or content inspection.
"""

from collections import defaultdict
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Optional Scapy import with defensive fallback
try:
    from scapy.all import IP, IPv6, TCP, UDP, rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def parse_pcap_file(pcap_source: Union[str, Path, bytes, io.BytesIO]) -> pd.DataFrame:
    """
    Parse a PCAP / PCAPNG packet capture file, reconstruct TCP/UDP bidirectional flows,
    and compute standard metadata metrics.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. PCAP parsing requires Scapy.")

    temp_path = None
    try:
        if isinstance(pcap_source, (bytes, io.BytesIO)):
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
                content = pcap_source.getvalue() if isinstance(pcap_source, io.BytesIO) else pcap_source
                tf.write(content)
                temp_path = Path(tf.name)
            pcap_file_path = str(temp_path)
        else:
            pcap_file_path = str(pcap_source)

        packets = rdpcap(pcap_file_path)
        return extract_flows_from_packets(packets)
    finally:
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


def extract_flows_from_packets(packets) -> pd.DataFrame:
    """
    Aggregate Scapy packet list into bidirectional conversational flows.
    """
    # Key: canonical 5-tuple (ip1, port1, ip2, port2, proto) where ip1 <= ip2
    flows = defaultdict(lambda: {
        "forward": [],
        "backward": [],
        "fwd_ip": None,
        "fwd_port": None,
        "bwd_ip": None,
        "bwd_port": None,
        "proto": "TCP"
    })

    for pkt in packets:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            continue

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_time = float(pkt.time)
        pkt_len = len(pkt)

        # Transport layer
        if pkt.haslayer(TCP):
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            proto = "TCP"
            tcp_flags = int(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            proto = "UDP"
            tcp_flags = 0
        else:
            continue

        # Canonical key
        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)
        if endpoint1 <= endpoint2:
            flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
            direction = "forward"
        else:
            flow_key = (dst_ip, dst_port, src_ip, src_port, proto)
            direction = "backward"

        flow_data = flows[flow_key]
        if direction == "forward":
            if flow_data["fwd_ip"] is None:
                flow_data["fwd_ip"] = src_ip
                flow_data["fwd_port"] = src_port
                flow_data["bwd_ip"] = dst_ip
                flow_data["bwd_port"] = dst_port
                flow_data["proto"] = proto
            flow_data["forward"].append((pkt_time, pkt_len, tcp_flags))
        else:
            if flow_data["bwd_ip"] is None:
                flow_data["bwd_ip"] = src_ip
                flow_data["bwd_port"] = src_port
                flow_data["fwd_ip"] = dst_ip
                flow_data["fwd_port"] = dst_port
                flow_data["proto"] = proto
            flow_data["backward"].append((pkt_time, pkt_len, tcp_flags))

    # Compute flow summary features
    session_rows: List[Dict[str, Any]] = []

    for key, data in flows.items():
        fwd_pkts = data["forward"]
        bwd_pkts = data["backward"]
        all_pkts = fwd_pkts + bwd_pkts

        if not all_pkts:
            continue

        all_pkts.sort(key=lambda x: x[0])  # Sort by timestamp
        start_time = all_pkts[0][0]
        end_time = all_pkts[-1][0]
        duration = max(end_time - start_time, 0.0001)

        fwd_count = len(fwd_pkts)
        bwd_count = len(bwd_pkts)
        tot_count = fwd_count + bwd_count

        fwd_lengths = [p[1] for p in fwd_pkts] if fwd_pkts else [0]
        bwd_lengths = [p[1] for p in bwd_pkts] if bwd_pkts else [0]
        all_lengths = [p[1] for p in all_pkts]

        fwd_bytes = sum(fwd_lengths)
        bwd_bytes = sum(bwd_lengths)
        tot_bytes = fwd_bytes + bwd_bytes

        # Inter-arrival times
        timestamps = [p[0] for p in all_pkts]
        iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([0.0])
        flow_iat_mean = float(np.mean(iats)) if len(iats) > 0 else 0.0
        flow_iat_std = float(np.std(iats)) if len(iats) > 0 else 0.0

        fwd_ts = [p[0] for p in fwd_pkts]
        fwd_iats = np.diff(fwd_ts) if len(fwd_ts) > 1 else np.array([0.0])
        fwd_iat_mean = float(np.mean(fwd_iats)) if len(fwd_iats) > 0 else 0.0

        bwd_ts = [p[0] for p in bwd_pkts]
        bwd_iats = np.diff(bwd_ts) if len(bwd_ts) > 1 else np.array([0.0])
        bwd_iat_mean = float(np.mean(bwd_iats)) if len(bwd_iats) > 0 else 0.0

        # TCP Flag parsing
        syn_count = sum(1 for p in all_pkts if (p[2] & 0x02) != 0)
        fin_count = sum(1 for p in all_pkts if (p[2] & 0x01) != 0)
        rst_count = sum(1 for p in all_pkts if (p[2] & 0x04) != 0)
        psh_count = sum(1 for p in all_pkts if (p[2] & 0x08) != 0)
        ack_count = sum(1 for p in all_pkts if (p[2] & 0x10) != 0)

        iso_ts = datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat()
        session_id = f"PCAP-{abs(hash(key)) % 1000000:06d}"

        session_rows.append({
            "session_id": session_id,
            "timestamp": iso_ts,
            "src_ip": data["fwd_ip"] or "127.0.0.1",
            "dst_ip": data["bwd_ip"] or "127.0.0.1",
            "dst_port": data["bwd_port"] or 443,
            "protocol": f"{data['proto']}/TLS",
            "flow_duration": round(duration, 4),
            "total_fwd_packets": fwd_count,
            "total_bwd_packets": bwd_count,
            "total_fwd_bytes": round(float(fwd_bytes), 1),
            "total_bwd_bytes": round(float(bwd_bytes), 1),
            "fwd_packet_length_mean": round(float(np.mean(fwd_lengths)), 2),
            "bwd_packet_length_mean": round(float(np.mean(bwd_lengths)), 2),
            "flow_bytes_per_sec": round(float(tot_bytes / duration), 2),
            "flow_packets_per_sec": round(float(tot_count / duration), 2),
            "flow_iat_mean": round(flow_iat_mean, 4),
            "flow_iat_std": round(flow_iat_std, 4),
            "fwd_iat_mean": round(fwd_iat_mean, 4),
            "bwd_iat_mean": round(bwd_iat_mean, 4),
            "packet_length_mean": round(float(np.mean(all_lengths)), 2),
            "packet_length_std": round(float(np.std(all_lengths)), 2),
            "syn_flag_count": syn_count,
            "rst_flag_count": rst_count,
            "psh_flag_count": psh_count,
            "ack_flag_count": ack_count,
            "fin_flag_count": fin_count,
            "down_up_ratio": round(float(bwd_count / max(fwd_count, 1)), 2)
        })

    return pd.DataFrame(session_rows)
