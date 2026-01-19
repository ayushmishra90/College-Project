from os_ken.base import app_manager
from os_ken.ofproto import ofproto_v1_3
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls

class SimpleLogger(app_manager.OSKenApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLogger, self).__init__(*args, **kwargs)
        self.logger.info("OSKen controller started")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0,
                                match=match, instructions=inst)
        dp.send_msg(mod)

        self.logger.info("Table-miss entry installed on switch %s", dp.id)
