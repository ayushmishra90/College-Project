#!/usr/bin/env python3
"""
dataset_builder.py
Post-processes flow_stats.csv and port_stats.csv into a merged mendeley_sdn_dataset.csv.
This script is optional because controller already writes merged rows, but it helps
to recompute or validate the merged dataset offline.
"""
import csv, os, time
from collections import defaultdict

OUTPUT_DIR = "output"
FLOW_CSV = os.path.join(OUTPUT_DIR, "flow_stats.csv")
PORT_CSV = os.path.join(OUTPUT_DIR, "port_stats.csv")
MERGED_CSV = os.path.join(OUTPUT_DIR, "mendeley_sdn_dataset_rebuilt.csv")

HEADER = [
    "dt","switch","src","dst","pktcount","bytecount","dur","dur_nsec","tot_dur",
    "flows","packetins","pktperflow","byteperflow","pktrate","Protocol","port_no",
    "tx_bytes","rx_bytes","tx_kbps","rx_kbps","tot_kbps","dt2","label"
]

# Load port stats snapshots keyed by (timestamp_floor, dpid, port_no) -> last seen bytes
def load_port_stats():
    port_map = defaultdict(dict)
    if not os.path.exists(PORT_CSV):
        print("No port csv found:", PORT_CSV)
        return port_map
    with open(PORT_CSV) as f:
        r = csv.DictReader(f)
        for row in r:
            ts = int(row['timestamp'])
            dpid = int(row['switch_id'])
            port = int(row['port_no'])
            key = (dpid, port)
            # keep most recent
            port_map[key] = {
                "timestamp": ts,
                "rx_bytes": int(row['rx_bytes']),
                "tx_bytes": int(row['tx_bytes']),
                "rx_packets": int(row['rx_packets']),
                "tx_packets": int(row['tx_packets'])
            }
    return port_map

def build_merged():
    port_map = load_port_stats()
    if not os.path.exists(FLOW_CSV):
        print("No flow csv found:", FLOW_CSV)
        return
    with open(FLOW_CSV) as f_in, open(MERGED_CSV, "w", newline="") as f_out:
        r = csv.DictReader(f_in)
        w = csv.writer(f_out)
        w.writerow(HEADER)
        for row in r:
            ts = int(row['timestamp'])
            dpid = int(row['switch_id'])
            src_mac = row.get('src_mac') or ""
            dst_mac = row.get('dst_mac') or ""
            pktcount = int(row.get('packet_count', 0))
            bytecount = int(row.get('byte_count', 0))
            dur = int(row.get('duration_sec', 0))
            dur_nsec = 0
            tot_dur = dur + dur_nsec/1e9
            flows = 0
            packetins = 0
            pktperflow = pktcount
            byteperflow = bytecount
            pktrate = pktperflow / 30.0
            Protocol = ""
            port_no = None
            tx_bytes = 0
            rx_bytes = 0
            tx_kbps = 0.0
            rx_kbps = 0.0
            tot_kbps = 0.0
            dt2 = ts
            label = 0
            # attempt to lookup port 1/2/3 for enrichment (best-effort)
            for p in [1,2,3]:
                pk = (dpid, p)
                if pk in port_map:
                    tx_bytes = port_map[pk]['tx_bytes']
                    rx_bytes = port_map[pk]['rx_bytes']
                    # can't compute exact kbps without interval, leave 0
                    port_no = p
                    break
            w.writerow([ts, dpid, "", "", pktcount, bytecount, dur, dur_nsec, tot_dur,
                        flows, packetins, pktperflow, byteperflow, pktrate, Protocol,
                        port_no, tx_bytes, rx_bytes, tx_kbps, rx_kbps, tot_kbps, dt2, label])
    print("Merged dataset written to:", MERGED_CSV)

if __name__ == "__main__":
    build_merged()
