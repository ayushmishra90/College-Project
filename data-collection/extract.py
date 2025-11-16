import pyshark
import pandas as pd
import os
from collections import defaultdict

PCAP_DIR = "/tmp/"
CSV_OUTPUT = "/tmp/flow_dataset_features.csv"
METADATA_CSV = "/tmp/dataset_metadata.csv"

metadata = pd.read_csv(METADATA_CSV)
flow_features = []

print("=== Starting PCAP Extraction ===")

for idx, row in metadata.iterrows():
    pcap_file = row["pcap_file"]
    label = row["scenario"]

    if not os.path.exists(pcap_file):
        print(f"[MISSING] {pcap_file}")
        continue

    print(f"[OK] Processing {pcap_file} ({label})")

    cap = pyshark.FileCapture(
        pcap_file,
        keep_packets=False,
        use_json=True,
        include_raw=False
    )

    flows = defaultdict(list)

    for pkt in cap:
        try:
            # -------------------------
            # IP / IPv6 parsing
            # -------------------------
            if "IP" in pkt:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                protocol = pkt.ip.proto
            elif "IPV6" in pkt:
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst
                protocol = pkt.ipv6.nxt
            else:
                continue

            # -------------------------
            # Transport Layer
            # -------------------------
            src_port = dst_port = 0
            tcp_flags = 0
            l4_proto = ""

            if "TCP" in pkt:
                l4_proto = "TCP"
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                tcp_flags = int(pkt.tcp.flags, 16)

            elif "UDP" in pkt:
                l4_proto = "UDP"
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)

            elif "ICMP" in pkt or "ICMPV6" in pkt:
                l4_proto = "ICMP"

            else:
                continue

            # -------------------------
            # FLOW ID
            # -------------------------
            flow_id = (src_ip, dst_ip, src_port, dst_port, l4_proto)

            # -------------------------
            # STORE PACKET FEATURES
            # -------------------------
            flows[flow_id].append({
                "timestamp": float(pkt.sniff_timestamp),
                "length": int(pkt.length),
                "tcp_flags": tcp_flags
            })

        except Exception:
            continue

    cap.close()

    # -------------------------
    # AGGREGATE FLOW FEATURES
    # -------------------------
    for flow_id, packets in flows.items():
        timestamps = [p["timestamp"] for p in packets]
        lengths = [p["length"] for p in packets]
        flags = [p["tcp_flags"] for p in packets]

        flow_features.append({
            "src_ip": flow_id[0],
            "dst_ip": flow_id[1],
            "src_port": flow_id[2],
            "dst_port": flow_id[3],
            "protocol": flow_id[4],
            "packet_count": len(packets),
            "total_bytes": sum(lengths),
            "min_packet": min(lengths),
            "max_packet": max(lengths),
            "mean_packet": sum(lengths) / len(lengths),
            "flow_duration": max(timestamps) - min(timestamps),
            "tcp_flags_sum": sum(flags),
            "label": label
        })

# Write to CSV
df = pd.DataFrame(flow_features)
df.to_csv(CSV_OUTPUT, index=False)

print(f"=== DONE ===")
print(f"Flow features written to: {CSV_OUTPUT}")
