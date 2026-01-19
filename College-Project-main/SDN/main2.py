#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


class SDN_DebugLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDN_DebugLogger, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    # -----------------------------
    # Switch connects
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.info(f"Register datapath: {dp.id}")
                self.datapaths[dp.id] = dp
        elif ev.state == CONFIG_DISPATCHER:
            return
        else:
            if dp.id in self.datapaths:
                self.logger.info(f"Unregister datapath: {dp.id}")
                del self.datapaths[dp.id]

    # -----------------------------
    # Install table-miss
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("Installed table-miss on switch")

    # -----------------------------
    # Periodic stats polling
    # -----------------------------
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        # Flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Port stats
        req = parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    # -----------------------------
    # Flow stats reply
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info("======= FLOW STATS RECEIVED =======")

        for stat in body:
            match = stat.match

            eth_type = match.get("eth_type")
            ipv4_src = match.get("ipv4_src")
            ipv4_dst = match.get("ipv4_dst")
            ipv6_src = match.get("ipv6_src")
            ipv6_dst = match.get("ipv6_dst")
            ip_proto = match.get("ip_proto")

            self.logger.info("Raw match: %s", match)

            self.logger.info(
                "eth_type=%s | ip_proto=%s | ipv4_src=%s | ipv4_dst=%s | ipv6_src=%s | ipv6_dst=%s",
                eth_type, ip_proto, ipv4_src, ipv4_dst, ipv6_src, ipv6_dst
            )

            self.logger.info(
                "packets=%s bytes=%s duration=%ss",
                stat.packet_count, stat.byte_count, stat.duration_sec
            )

    # -----------------------------
    # Port stats reply
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info("======= PORT STATS =======")

        for stat in body:
            self.logger.info(
                "port %s: rx_packets=%s tx_packets=%s rx_bytes=%s tx_bytes=%s",
                stat.port_no,
                stat.rx_packets, stat.tx_packets,
                stat.rx_bytes, stat.tx_bytes
            )
