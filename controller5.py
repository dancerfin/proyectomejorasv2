from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib import hub
import csv
import statistics
from datetime import datetime
from ml import MachineLearningAlgo
import joblib
import os

# Configuración global
APP_TYPE = 1  # 0: datacollection, 1: ddos detection
PREVENTION = 1  # DDoS prevention
TEST_TYPE = 0   # 0: normal, 1: attack (solo para datacollection)
INTERVAL = 5    # Intervalo de monitoreo (segundos)

# Estructuras globales
gflows = {}
iteration = {}
old_ssip_len = {}
prev_flow_count = {}
flow_cookie = {}
BLOCKED_PORTS = {}
keystore = {}

def get_iteration(dpid):
    global iteration
    iteration.setdefault(dpid, 0)
    return iteration[dpid]

def set_iteration(dpid, count):
    global iteration
    iteration[dpid] = count

def get_old_ssip_len(dpid):
    global old_ssip_len
    old_ssip_len.setdefault(dpid, 0)
    return old_ssip_len[dpid]

def set_old_ssip_len(dpid, count):
    global old_ssip_len
    old_ssip_len[dpid] = count

def get_prev_flow_count(dpid):
    global prev_flow_count
    prev_flow_count.setdefault(dpid, 0)
    return prev_flow_count[dpid]

def set_prev_flow_count(dpid, count):
    global prev_flow_count
    prev_flow_count[dpid] = count

def get_flow_number(dpid):
    global flow_cookie
    flow_cookie.setdefault(dpid, 0)
    flow_cookie[dpid] += 1
    return flow_cookie[dpid]

def get_time():
    return datetime.now()

def calculate_value(key, val):
    key = str(key).replace(".", "_")
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) 
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0

# Manejo de archivos CSV
def init_portcsv(dpid):
    if APP_TYPE == 0:
        with open(f"switch_{dpid}_data.csv", 'a') as f:
            csv.writer(f).writerow(["time", "sfe", "ssip", "rfip", "sdfp", "sdfb", "type"])

def update_portcsv(dpid, row):
    if APP_TYPE == 0:
        with open(f"switch_{dpid}_data.csv", 'a') as f:
            row.append(str(TEST_TYPE))
            csv.writer(f).writerow(row)

def update_resultcsv(row):
    if APP_TYPE == 0:
        with open("result.csv", 'a') as f:
            row.append(str(TEST_TYPE))
            csv.writer(f).writerow(row)

class DDoSML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = MachineLearningAlgo() if APP_TYPE == 1 else None
        self.flow_thread = hub.spawn(self._flow_monitor)

    def _flow_monitor(self):
        hub.sleep(INTERVAL * 2)
        while True:
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        self.datapaths[dpid] = datapath
        self.mac_to_port[dpid] = {}
        self.arp_ip_to_port[dpid] = {}
        BLOCKED_PORTS[dpid] = []

        # Flujo por defecto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions, get_flow_number(dpid))

        # Flujo para ARP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 10, match, actions, get_flow_number(dpid))

        init_portcsv(dpid)
        self.logger.info(f"Switch {dpid} conectado")

    def request_flow_metrics(self, datapath):
        datapath.send_msg(datapath.ofproto_parser.OFPFlowStatsRequest(datapath))

    def _speed_of_flow_entries(self, dpid, flows):
        curr = len(flows)
        sfe = curr - get_prev_flow_count(dpid)
        set_prev_flow_count(dpid, curr)
        return sfe

    def _speed_of_source_ip(self, dpid, flows):
        ssip = {f.match['ipv4_src'] for f in flows if 'ipv4_src' in f.match}
        curr = len(ssip)
        res = curr - get_old_ssip_len(dpid)
        set_old_ssip_len(dpid, curr)
        return res

    def _ratio_of_flowpair(self, dpid, flows):
        flow_pairs = {
            frozenset({f.match['ipv4_src'], f.match['ipv4_dst']}) 
            for f in flows if 'ipv4_src' in f.match and 'ipv4_dst' in f.match
        }
        return len(flow_pairs) * 2 / max(len(flows) - 1, 1)

    def _stddev_packets(self, dpid, flows):
        pkts, bytes_ = [], []
        for f in flows:
            if 'ipv4_src' in f.match and 'ipv4_dst' in f.match:
                key = f"switch_{dpid}_{f.match['ipv4_src']}_{f.match['ipv4_dst']}"
                pkts.append(calculate_value(f"{key}.packets", f.packet_count))
                bytes_.append(calculate_value(f"{key}.bytes", f.byte_count))
        
        try:
            return statistics.stdev(pkts) if pkts else 0, statistics.stdev(bytes_) if bytes_ else 0
        except:
            return 0, 0

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        gflows[dpid] = ev.msg.body

        if ev.msg.flags == 0:
            sfe = self._speed_of_flow_entries(dpid, gflows[dpid])
            ssip = self._speed_of_source_ip(dpid, gflows[dpid])
            rfip = self._ratio_of_flowpair(dpid, gflows[dpid])
            sdfp, sdfb = self._stddev_packets(dpid, gflows[dpid])

            timestamp = get_time().strftime("%Y-%m-%d %H:%M:%S")
            metrics_row = [timestamp, str(sfe), str(ssip), str(rfip), str(sdfp), str(sdfb)]

            if APP_TYPE == 1 and get_iteration(dpid) == 1:
                result, confidence = self.mlobj.classify([sfe, ssip, rfip, sdfp, sdfb])
                
                if '1' in result:
                    self.logger.warning(f"DDoS detectado! Confianza: {confidence:.2f}")
                    self.mitigation = 1
                    if PREVENTION == 1:
                        self._activate_prevention(dpid)
                else:
                    self.logger.info(f"Tráfico normal. Confianza: {confidence:.2f}")
            else:
                update_portcsv(dpid, metrics_row)
                update_resultcsv([str(sfe), str(ssip), str(rfip), str(sdfp), str(sdfb)])

            set_iteration(dpid, 1)
            gflows[dpid] = []

    def _activate_prevention(self, dpid):
        datapath = self.datapaths.get(dpid)
        if datapath:
            for port in self.arp_ip_to_port[dpid]:
                if port not in BLOCKED_PORTS[dpid]:
                    self.block_port(datapath, port)
                    BLOCKED_PORTS[dpid].append(port)
                    self.logger.info(f"Bloqueado puerto {port} en switch {dpid}")

    def add_flow(self, datapath, priority, match, actions, serial_no, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=serial_no,
            buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def block_port(self, datapath, port):
        match = datapath.ofproto_parser.OFPMatch(in_port=port)
        self.add_flow(datapath, 100, match, [], get_flow_number(datapath.id))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Inicializar estructuras
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        BLOCKED_PORTS.setdefault(dpid, [])

        # Aprender dirección MAC
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        # Manejar ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

        # Instalar flujo
        if out_port != ofproto.OFPP_FLOOD and eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                if self.mitigation and PREVENTION:
                    if (in_port not in BLOCKED_PORTS[dpid] and 
                        ip_pkt.src not in self.arp_ip_to_port[dpid].get(in_port, [])):
                        self.block_port(datapath, in_port)
                        BLOCKED_PORTS[dpid].append(in_port)
                        return

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
                self.add_flow(
                    datapath, 1, match, 
                    [parser.OFPActionOutput(out_port)],
                    get_flow_number(dpid),
                    msg.buffer_id
                )
                return

        # Enviar paquete
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)],
            data=data
        )
        datapath.send_msg(out)

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()