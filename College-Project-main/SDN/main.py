from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import hub  # for periodic tasks
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.mac import haddr_to_bin
from ryu.lib import addrconv

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}   # store datapaths (switches)
        self.monitor_thread = hub.spawn(self._monitor)  # start monitoring loop

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        """Track switch connections."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == 'DEAD':
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        """Request stats from all datapaths every 30s."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(30)

    # def _request_stats(self, datapath):
    #     print("sending request to swicth....")
    #     """Send Flow and Port Stats requests."""
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     # Request Flow Stats
    #     req = parser.OFPFlowStatsRequest(datapath)
    #     datapath.send_msg(req)

    #     # Request Port Stats
    #     req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
    #     datapath.send_msg(req)

    def _request_stats(self, datapath):
        print("sending request to switch....")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Request Flow Stats (OF1.0 requires match, table_id, out_port, flags)
        match = parser.OFPMatch()  # empty = match all flows
        req = parser.OFPFlowStatsRequest(
            datapath=datapath,
            match=match,
            table_id=0xff,        # all tables
            out_port=ofproto.OFPP_NONE,
            flags=0
        )
        datapath.send_msg(req)

        # Request Port Stats
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
        datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow stats reply from switch."""
        dpid = ev.msg.datapath.id   # Switch ID (DPID)
        for stat in ev.msg.body:
            src_mac = addrconv.mac.bin_to_text(stat.match.dl_src)
            dst_mac = addrconv.mac.bin_to_text(stat.match.dl_dst)
            self.logger.info(
                "s=%s Flow: src=%s dst=%s packets=%d bytes=%d duration=%ds",
                dpid,
                src_mac, dst_mac,
                stat.packet_count, stat.byte_count,
                stat.duration_sec
            )

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port stats reply from switch."""
        dpid = ev.msg.datapath.id   # Switch ID (DPID)
        for stat in ev.msg.body:
            
            self.logger.info(
                "s=%s Port %d: rx_packets=%d tx_packets=%d rx_bytes=%d tx_bytes=%d",
                dpid,
                stat.port_no, stat.rx_packets, stat.tx_packets,
                stat.rx_bytes, stat.tx_bytes
            )

    # ---- Your existing learning switch code (packet_in, add_flow, etc.) ----
    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
