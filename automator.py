from pox.core import core
import pox

from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr,IPAddr

import re
import time


class Automator(object):

    def _handle_ConnectionUp(self,event):
        self.switch_count += 1
        if self.switch_count == self.switch_limit:
            self.type_decider(event)

    def __init__(self, rules, rules_values, host_ips, host_names, switch):
        self.rules = rules
        self.rules_values = rules_values
        self.host_ips = host_ips
        self.host_names = host_names
        self.switch_count = 0
        self.switch_limit = int(switch)
        core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
        #core.openflow.addListenerByName("FlowStatsReceived", self._handle_switch_flow_stats) 
        #core.openflow.addListenerByName("PortStatsReceived", self._handle_switch_stats)
    
    def hostname_to_ip_for_from(self,rule):
        match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule.get("from"))
        r_src = None
        if match:
          r_src = rule.get("from")
        else:
          r_src = self.host_names.get(rule.get("from"))
        return r_src
    
    def hostname_to_ip_for_to(self,rule):
        if rule.get("to"): # if the rule has specified a destination
            match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule.get("to"))
            r_dst = None
            if match:
                r_dst = rule.get("to")
            else:
                r_dst = self.host_names.get(rule.get("to"))
            return r_dst
        else:
            if self.hostname_to_ip_for_from(rule) == "10.0.1.100":
                return "10.0.1.101"
            else:
                return "10.0.1.100"
    
    def get_src_port(self, rule):
        if rule.get("sport"):
            return rule.get("sport")
        else:
            return "48966" # found by doing iperf on mininet
    
    def get_dst_port(self, rule):
        if rule.get("dport"):
            return rule.get("dport")
        else:
            return "5001" # found by doing iperf on mininet
    
    def type_decider(self,event):
        for rule in self.rules_values:
            if "ICMP" in rule["prot"]:
                #print "icmp"
                src =  self.hostname_to_ip_for_from(rule)
                dst =  self.hostname_to_ip_for_to(rule)
                ping = self.create_ping(src, dst)
                self.send_packets(event, ping)
                #ping = self.create_ping(dst, src)
                #self.send_packets(event, ping)
            elif "UDP" in rule["prot"]:
                #print "udp"
                src =  self.hostname_to_ip_for_from(rule)
                dst =  self.hostname_to_ip_for_to(rule)
                sport = self.get_src_port(rule)
                dport = self.get_dst_port(rule)
                udp = self.create_udp(src, dst, sport, dport)
                self.send_packets(event, udp)
            elif "TCP" in rule["prot"]:
                #print "tcp"
                src =  self.hostname_to_ip_for_from(rule)
                dst =  self.hostname_to_ip_for_to(rule)
                sport = self.get_src_port(rule)
                dport = self.get_dst_port(rule)
                tcp = self.create_tcp(src, dst, sport, dport)
                self.send_packets(event, tcp)
            else:
                pass
    
    def create_udp(self, src, dst, sport, dport):
        # Create UDP packet:
        udp = pkt.udp()
        udp.srcport = int(sport)
        udp.dstport = int(dport)
        #print "this is the udp", udp
        # Create the IP:
        ip = pkt.ipv4()
        ip.protocol = ip.UDP_PROTOCOL
        ip.srcip = IPAddr(src)
        ip.dstip = IPAddr(dst)
        ip.payload = udp
        #print "THis is the ip", ip
        return ip
    
    def create_tcp(self, src, dst, sport, dport):
        # Create TCP:
        tcp = pkt.tcp()
        tcp.srcport = int(sport)
        tcp.dstport = int(dport)
        tcp._setflag(tcp.SYN_flag,1)
        tcp.seq = 0
        tcp.ack = 0
        tcp.win = 1
        tcp.off = 5
        #print tcp
        
        # Create the IP:
        ip = pkt.ipv4()
        ip.protocol = ip.TCP_PROTOCOL
        ip.srcip = IPAddr(src)
        ip.dstip = IPAddr(dst)
        ip.payload = tcp
        #print ip
        return ip

    def create_ping(self, src, dst):
        # Make a ping request:
        icmp = pkt.icmp()
        icmp.type = pkt.TYPE_ECHO_REQUEST
        echo = pkt.ICMP.echo(payload = "0123456789")
        icmp.payload = echo
        #print "THis is the ping:", icmp

        #Create IP packet
        ip = pkt.ipv4()
        ip.protocol = ip.ICMP_PROTOCOL
        ip.srcip = IPAddr(src)
        ip.dstip = IPAddr(dst)
        ip.payload = icmp
        #print "THis is the ip", ip
        return ip

    def send_packets(self, event, ip_packet):
        #Create Ethernet Payload
        eth = ethernet()
        eth.src = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.type = eth.IP_TYPE
        eth.payload = ip_packet
        #print "This is the ethenret", eth

        msg = of.ofp_packet_out()
        #msg.actions.append(of.ofp_action_output(port = 1))
        msg.data =  eth.pack()
        msg.in_port = of.OFPP_NONE
        #for i in range(5): # send packet untill 5 port ranges
            #msg.actions.append(of.ofp_action_output(port = i + 1))
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
            #core.openflow.getConnection(event.dpid).send(msg)
