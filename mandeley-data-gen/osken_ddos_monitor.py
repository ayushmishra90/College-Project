#!/usr/bin/env python3
"""
Robust OS-Ken controller for Mendeley-style SDN DDoS dataset generation.

Changes vs earlier:
 - installs table-miss on EventOFPSwitchFeatures (ensures flows exist)
 - logs state values from EventOFPStateChange
 - more defensive / verbose logs so you can quickly see what happens
 - same output CSV structure (23 columns) as requested
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub

import time, datetime, csv, os, logging

MONITOR_INTERVAL = 30                 # seconds
OUTPUT_CSV = "dataset/sdn_ddos_dataset.csv"
LABEL_FILE = "dataset/label_flag.txt"

# Setup root logger to print to stdout (when running --verbose osken-manager you also get osken logging)
logging.basicConfig(level=logging.INFO)

class OSKenDDOSMonitor(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSKenDDOSMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}            # dpid -> datapath
        self.packet_in_count = {}      # dpid -> count (since last write)

        # Ensure dataset dir
        if not os.path.exists("dataset"):
            os.makedirs("dataset")

        # Prepare CSV (append if exists)
        new_file = not os.path.exists(OUTPUT_CSV)
        self.csvfile = open(OUTPUT_CSV, "a", newline="")
        self.writer = csv.writer(self.csvfile)
        if new_file:
            self.writer.writerow([
                "dt","dt_epoch","switch_id",
                "src_ip","dst_ip","src_port","dst_port","protocol",
                "packet_count","byte_count","duration_sec","duration_nsec",
                "tx_packets","rx_packets","tx_bytes","rx_bytes",
                "tx_kbps","rx_kbps","bw","packet_rate",
                "flow_entries","packet_in_count","label"
            ])
            self.csvfile.flush()

        # Start monitor thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("OSKenDDOSMonitor started: MONITOR_INTERVAL=%s", MONITOR_INTERVAL)

    # Install table-miss when switch features arrive (this guarantees flow entries get recorded)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        self.logger.info("EventOFPSwitchFeatures from datapath %s — installing table-miss", dpid)

        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        try:
            dp.send_msg(mod)
            self.logger.info("Table-miss flow installed on datapath %s (features handler)", dpid)
        except Exception as e:
            self.logger.error("Failed to send flow mod on features handler: %s", e)

        # Ensure structures exist
        self.datapaths.setdefault(dpid, dp)
        self.packet_in_count.setdefault(dpid, 0)
        dp._last_flows = None
        dp._last_ports = None
        dp._last_flow_count = 0

    # Track stats of the state change and install table-miss on MAIN_DISPATCHER
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        dpid = dp.id
        state = ev.state
        # For clarity, map numeric states to names if available
        state_name = {1: "MAIN_DISPATCHER", 2: "DEAD_DISPATCHER"}.get(state, str(state))
        self.logger.info("StateChange for dpid %s: %s", dpid, state_name)

        if state == MAIN_DISPATCHER:
            # Ensure datapath present
            self.datapaths[dpid] = dp
            self.packet_in_count.setdefault(dpid, 0)
            self.logger.info("Datapath %s recorded in datpaths (MAIN_DISPATCHER)", dpid)

            # also ensure table-miss present (defensive: in case features handler missed)
            try:
                ofp = dp.ofproto
                parser = dp.ofproto_parser
                match = parser.OFPMatch()
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
                dp.send_msg(mod)
                self.logger.info("Defensive table-miss installed on datapath %s (state_change)", dpid)
            except Exception as e:
                self.logger.error("Failed defensive table-miss install: %s", e)

        elif state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                del self.datapaths[dpid]
            self.logger.info("Datapath %s removed (DEAD_DISPATCHER)", dpid)

    # Count PACKET_IN events
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        dpid = ev.msg.datapath.id
        self.packet_in_count[dpid] = self.packet_in_count.get(dpid, 0) + 1
        self.logger.debug("PacketIn from dpid %s (total %s)", dpid, self.packet_in_count[dpid])

    # Polling loop: send stats requests every MONITOR_INTERVAL
    def _monitor(self):
        while True:
            if not self.datapaths:
                self.logger.info("No datapaths found — waiting for switches...")
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                try:
                    req_flow = parser.OFPFlowStatsRequest(dp)
                    dp.send_msg(req_flow)
                    req_port = parser.OFPPortStatsRequest(dp)
                    dp.send_msg(req_port)
                    self.logger.info("Sent Flow & Port stats request to dpid %s", dp.id)
                except Exception as e:
                    self.logger.error("Failed to send stats requests to %s: %s", getattr(dp, 'id', 'unknown'), e)
            hub.sleep(MONITOR_INTERVAL)

    # Flow stats reply handler
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        body = ev.msg.body
        flows = []

        for stat in body:
            try:
                src = stat.match.get("ipv4_src")
                dst = stat.match.get("ipv4_dst")
            except Exception:
                src = None
                dst = None
            if src is None or dst is None:
                continue
            sport = stat.match.get("tcp_src") or stat.match.get("udp_src") or 0
            dport = stat.match.get("tcp_dst") or stat.match.get("udp_dst") or 0
            proto = 6 if "tcp_src" in stat.match else (17 if "udp_src" in stat.match else 1)
            flows.append({
                "src": src, "dst": dst, "sport": int(sport), "dport": int(dport),
                "proto": proto,
                "packet_count": int(stat.packet_count),
                "byte_count": int(stat.byte_count),
                "duration_sec": int(stat.duration_sec),
                "duration_nsec": int(stat.duration_nsec)
            })

        dp._last_flows = flows
        dp._last_flow_count = len(flows)
        self.logger.info("FlowStatsReply from %s: %d flows (relevant)", dpid, dp._last_flow_count)

        if getattr(dp, "_last_ports", None) is not None:
            self._merge_and_write(dp)

    # Port stats reply handler
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        port_stats = []
        for stat in ev.msg.body:
            port_stats.append({
                "port_no": int(stat.port_no),
                "rx_packets": int(stat.rx_packets),
                "tx_packets": int(stat.tx_packets),
                "rx_bytes": int(stat.rx_bytes),
                "tx_bytes": int(stat.tx_bytes)
            })
        dp._last_ports = port_stats
        self.logger.info("PortStatsReply from %s: %d ports", dpid, len(port_stats))

        if getattr(dp, "_last_flows", None) is not None:
            self._merge_and_write(dp)

    # Merge flows + port aggregates and write rows
    def _merge_and_write(self, dp):
        dpid = dp.id
        flows = getattr(dp, "_last_flows", []) or []
        ports = getattr(dp, "_last_ports", []) or []

        # Read label
        label = 0
        try:
            with open(LABEL_FILE, "r") as f:
                s = f.read().strip()
                label = 1 if s == "1" else 0
        except Exception:
            label = 0

        # Port aggregates
        port_agg = {
            "tx_packets": 0, "rx_packets": 0, "tx_bytes": 0, "rx_bytes": 0,
            "tx_kbps": 0.0, "rx_kbps": 0.0, "bw": 0.0, "port_no": 0
        }
        if ports:
            total_tx_bytes = sum(p["tx_bytes"] for p in ports)
            total_rx_bytes = sum(p["rx_bytes"] for p in ports)
            total_tx_pkts = sum(p["tx_packets"] for p in ports)
            total_rx_pkts = sum(p["rx_packets"] for p in ports)
            tx_kbps = (total_tx_bytes * 8) / 1024.0 / MONITOR_INTERVAL
            rx_kbps = (total_rx_bytes * 8) / 1024.0 / MONITOR_INTERVAL
            bw = tx_kbps + rx_kbps
            port_agg = {
                "tx_packets": total_tx_pkts,
                "rx_packets": total_rx_pkts,
                "tx_bytes": total_tx_bytes,
                "rx_bytes": total_rx_bytes,
                "tx_kbps": tx_kbps,
                "rx_kbps": rx_kbps,
                "bw": bw,
                "port_no": ports[0]["port_no"]
            }

        flow_entries = len(flows)
        packet_in_cnt = self.packet_in_count.get(dpid, 0)

        ts = time.time()
        dt_iso = datetime.datetime.utcfromtimestamp(ts).isoformat()

        if flow_entries == 0:
            row = [
                dt_iso, ts, dpid,
                "", "", 0, 0, 0,
                0, 0, 0, 0,
                port_agg["tx_packets"], port_agg["rx_packets"],
                port_agg["tx_bytes"], port_agg["rx_bytes"],
                port_agg["tx_kbps"], port_agg["rx_kbps"], port_agg["bw"],
                0.0, flow_entries, packet_in_cnt, label
            ]
            self.writer.writerow(row)
            self.csvfile.flush()
            self.logger.info("Wrote aggregate row for dpid %s (no flows)", dpid)
        else:
            for f in flows:
                packet_rate = float(f["packet_count"]) / float(MONITOR_INTERVAL)
                row = [
                    dt_iso, ts, dpid,
                    f["src"], f["dst"], f["sport"], f["dport"], f["proto"],
                    f["packet_count"], f["byte_count"], f["duration_sec"], f["duration_nsec"],
                    port_agg["tx_packets"], port_agg["rx_packets"],
                    port_agg["tx_bytes"], port_agg["rx_bytes"],
                    port_agg["tx_kbps"], port_agg["rx_kbps"], port_agg["bw"],
                    packet_rate, flow_entries, packet_in_cnt, label
                ]
                self.writer.writerow(row)
            self.csvfile.flush()
            self.logger.info("Wrote %d flow rows for dpid %s", flow_entries, dpid)

        # Reset per-datapath holders & packet_in counter
        dp._last_flows = None
        dp._last_ports = None
        self.packet_in_count[dpid] = 0
