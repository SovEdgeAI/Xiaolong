from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import subprocess
from ryu.lib.packet import packet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import binascii
import os
import requests
import json

# ---------------------------------------------------------------------------
# QoS / bandwidth control
#
# Priorities in table 0 (the catch-all below is why this matters):
#   1000  GTP punt to controller  (DDoS detection path)
#    500  GTP rate-limit via meter  <-- installed here
#    100  actions=NORMAL            <-- catch-all, matches everything
#
# Anything at a priority below 100 is dead code: the priority-100 NORMAL rule
# already matches every packet. The pre-existing block path installs its rule at
# priority 1 and is therefore never reached, which is why the rate limiter is
# installed at 500 instead.
#
# Scope note: OVS cannot parse GTP. There is no gtp_teid match field and the
# inner IP header is opaque payload, so this meter polices the *aggregate*
# gNB<->UPF tunnel, not an individual UE or PDU session. Per-flow policing
# requires the P4 pipeline in approach2, which does parse GTP.
# ---------------------------------------------------------------------------
QOS_METER_ID = 1
QOS_FLOW_PRIORITY = 500
GTP_U_PORT = 2152
qos_instance_name = 'qos_api_app'


# Send all GTP traffic to the controller
# =================================================================================================================================
# Build switch flows
commands = [
    # Normal Switching
    'sudo ovs-ofctl -O OpenFlow13 add-flow br-ovs-ryu "table=0,cookie=0x0,priority=100,actions=normal"',
    # Capture GTP Traffic
    'sudo ovs-ofctl -O OpenFlow13 add-flow br-ovs-ryu "table=0,cookie=0x1,priority=1000,udp,tp_dst=2152,actions=controller"',
]
# These bootstrap flows need root. Failing to install them must not stop the
# controller from starting: they are static, survive a controller restart, and
# can be managed out-of-band with ovs-ofctl. Catching only CalledProcessError is
# not enough here - under eventlet's patched subprocess the raised class does not
# always match, and an escaped exception aborts app loading entirely.
# Set RYU_BOOTSTRAP_FLOWS=0 to skip this block (e.g. when running unprivileged).
if os.environ.get('RYU_BOOTSTRAP_FLOWS', '1') != '0':
    for i, command in enumerate(commands):
        try:
            output = subprocess.check_output(command, shell=True)
            print(output.decode())
            print("Flow {} of {} added".format(i + 1, len(commands)))
        except Exception as e:
            print(f"Warning: could not install bootstrap flow {i + 1}: {e}")

# Define the Ryu application
class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.datapath = None
        wsgi = kwargs['wsgi']
        wsgi.register(QoSController, {qos_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Keep a handle so the REST API can push meters at any time.
        self.datapath = ev.msg.datapath
        self.logger.info("Switch connected: dpid=%s", ev.msg.datapath_id)

    # -- meter plumbing -----------------------------------------------------

    def set_meter(self, rate_kbps, burst_kb=None):
        """Install or replace the rate-limiting meter and the flow that uses it.

        A DROP band polices anything above rate_kbps. OVS reports
        'band_types: drop' and 'capabilities: kbps pktps burst stats', so a
        single kbps drop band is the supported shape here (max_bands is 1).
        """
        dp = self.datapath
        if dp is None:
            return False, "no switch connected"
        ofp, parser = dp.ofproto, dp.ofproto_parser

        burst = burst_kb if burst_kb is not None else max(rate_kbps // 10, 16)
        band = parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=burst)

        # MODIFY fails if the meter does not exist yet, so delete-then-add
        # keeps this idempotent whether or not a meter is already present.
        dp.send_msg(parser.OFPMeterMod(datapath=dp, command=ofp.OFPMC_DELETE,
                                       meter_id=QOS_METER_ID, bands=[]))
        dp.send_msg(parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_ADD,
            flags=ofp.OFPMF_KBPS | ofp.OFPMF_BURST,
            meter_id=QOS_METER_ID, bands=[band]))

        # Match the GTP-U tunnel in both directions and meter it before
        # handing the packet to NORMAL forwarding.
        for match in (parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=GTP_U_PORT),
                      parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=GTP_U_PORT)):
            inst = [parser.OFPInstructionMeter(QOS_METER_ID, ofp.OFPIT_METER),
                    parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)])]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=QOS_FLOW_PRIORITY,
                command=ofp.OFPFC_ADD, match=match, instructions=inst))

        dp.send_msg(parser.OFPBarrierRequest(dp))
        self.logger.info("QoS: metering GTP-U at %s kbps (burst %s kb)", rate_kbps, burst)
        return True, "meter %s set to %s kbps" % (QOS_METER_ID, rate_kbps)

    def clear_meter(self):
        """Remove the rate-limit flows and the meter, restoring line rate."""
        dp = self.datapath
        if dp is None:
            return False, "no switch connected"
        ofp, parser = dp.ofproto, dp.ofproto_parser

        for match in (parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=GTP_U_PORT),
                      parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=GTP_U_PORT)):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=QOS_FLOW_PRIORITY,
                command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match))

        dp.send_msg(parser.OFPMeterMod(datapath=dp, command=ofp.OFPMC_DELETE,
                                       meter_id=QOS_METER_ID, bands=[]))
        dp.send_msg(parser.OFPBarrierRequest(dp))
        self.logger.info("QoS: rate limit cleared")
        return True, "meter %s cleared" % QOS_METER_ID


class QoSController(ControllerBase):
    """REST surface so the limit can be changed mid-iperf3-run.

      PUT    /qos/meter/5000   -> police GTP-U at 5000 kbps
      DELETE /qos/meter        -> restore line rate
    """

    def __init__(self, req, link, data, **config):
        super(QoSController, self).__init__(req, link, data, **config)
        self.app = data[qos_instance_name]

    def _reply(self, ok, msg):
        # webob refuses a text body without a charset, so hand it bytes.
        return Response(status=200 if ok else 503,
                        content_type='application/json',
                        body=json.dumps({'ok': ok, 'message': msg}).encode('utf-8'))

    @route('qos', '/qos/meter/{rate}', methods=['PUT'])
    def put_meter(self, req, **kwargs):
        try:
            rate = int(kwargs['rate'])
        except (TypeError, ValueError):
            return self._reply(False, 'rate must be an integer in kbps')
        ok, msg = self.app.set_meter(rate)
        return self._reply(ok, msg)

    @route('qos', '/qos/meter', methods=['DELETE'])
    def delete_meter(self, req, **kwargs):
        ok, msg = self.app.clear_meter()
        return self._reply(ok, msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        hex_data = binascii.hexlify(msg.data).decode('utf-8')

        # Initialize packets and extract details from the received packet
        pkt = packet.Packet(msg.data)

        # Extract source and destination IP addresses
        ue_src_ip_hex = msg.data[70:74]
        ue_dst_ip_hex = msg.data[74:78]

        # Convert the IP addresses to octets
        ue_src_ip = ".".join(map(str, ue_src_ip_hex))
        ue_dst_ip = ".".join(map(str, ue_dst_ip_hex))

        # Extract and convert the protocol to integer
        protocol = msg.data[67]

        # Get the size of the packet in bytes
        size = len(msg.data)

        # Check if the source IP is blocked
        blocked_ip_url = f"http://127.0.0.1:23000/blocked-ips/{ue_src_ip}"
        try:
            response = requests.get(blocked_ip_url)
            if response.status_code == 200:
                blocked_info = response.json()
                match = ofp_parser.OFPMatch(in_port=msg.match['in_port'])
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_CLEAR_ACTIONS, [])]
                mod = ofp_parser.OFPFlowMod(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, priority=1, match=match, instructions=inst)
                dp.send_msg(mod)
                return
            elif response.status_code == 404:
                print(f"Source IP {ue_src_ip} is not blocked.")

                # Send the packet out to the original destination
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
                out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=msg.match['in_port'], actions=actions, data=msg.data)
                dp.send_msg(out)

                # Update flow data
                flow_url = f"http://127.0.0.1:23000/flow/{ue_src_ip}-{ue_dst_ip}-{protocol}"
                flow_data = {
                    "bytes": size
                }
                try:
                    flow_response = requests.put(flow_url, data=json.dumps(flow_data), headers={'Content-Type': 'application/json'})
                    if flow_response.status_code == 200:
                        print("Flow data updated successfully.")
                    else:
                        print(f"Error updating flow data: {flow_response.status_code}")
                except requests.exceptions.RequestException as e:
                    print(f"HTTP request failed: {e}")

            else:
                print(f"Error checking blocked IP status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"HTTP request failed: {e}")
