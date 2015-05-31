#########################################
# Network wide tcpdump
# @Author Haris Sistek
#########################################

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
import pox.lib.packet as packet
import datetime, time
from pox.openflow.of_json import *
import re
import violation_checker as vc # see file violation_checker.py

# spanning tree protocol from pox
import pox.openflow.discovery as discov
import pox.openflow.spanning_tree as spanning_tree

log = core.getLogger()

# Layer 1 Vars:
checker = None # violation_checker class var, declared in launch()
layer1_correct = True # Helps us decide what layer we should search on
last_packet = None # The packet that triggered the violation

# Port stat vars:
count = 0
dev_port_ip = {}
known_maps = []

# Remember number of bytes sent:
ip_bytes_sent = {}
ip_packets_sent = {}
ip_bytes_recv = {}
ip_packets_recv = {}

# Layer 2 Vars:
yet_to_do = True
switch_count = 0

'''
Will map IP to port/dev relationship
'''
def add_host(dev,port,ip):
    global dev_port_ip
    global known_maps
    if ip in known_maps:
        return

    if dev_port_ip.get(dev):
        info = dev_port_ip.get(dev)
        info[ip] = port
        info[port] = ip
        dev_port_ip[dev] = info
        known_maps.append(ip) # just map once
        return

    info = {}
    info[ip] = port
    info[port] = ip
    dev_port_ip[dev] = info
    known_maps.append(ip) # just map once

'''
Update lates port stats given from network devices, map to IP
'''
def add_port_entry(ip, bsent, brecv, psent, precv):
    global ip_bytes_sent
    global ip_bytes_recv
    global ip_packets_sent
    global ip_packets_recv

    ip_bytes_sent[ip] = bsent
    ip_bytes_recv[ip] = brecv
    ip_packets_sent[ip] = psent
    ip_packets_recv[ip] = precv


def handle_port_stats(event):
    stats = event.stats
    for stat in stats:
      if dev_port_ip.get(dpid_to_str(event.dpid)):# if entry exists
        if dev_port_ip.get(dpid_to_str(event.dpid)).get(stat.port_no):# if entry exists
          add_port_entry(dev_port_ip[dpid_to_str(event.dpid)][stat.port_no], stat.tx_bytes,
                         stat.rx_bytes, stat.tx_packets, stat.rx_packets)
    if layer1_correct:
        if checker:
            violation = checker.check_if_ports_legal(ip_bytes_sent, 
                                            ip_bytes_recv, ip_packets_sent, ip_packets_recv)
            decider(violation, None)

def handle_flow_requests(event):
    stats = flow_stats_to_list(event.stats)
    ips = None
    ports = None
    if last_packet:
        match = re.search(r'ip\s+(?P<ip_src>.+)\s+>\s+(?P<ip_dst>.+):\s+', last_packet)
        if match:
            ips = match.groupdict()
            
        match2 = re.search(r'srcp\s+(?P<sport>\d+)\s+dstp\s+(?P<dport>\d+)', last_packet)
        if match2:
            ports = match2.groupdict()
            
    
    print "## Flow Table for Deivce:", event.dpid, "##"
    entry = 1
    for stat in stats:
        print "> Entry %d Match:" % entry
        print stat["match"]
        print ">> Entry Action"
        print stat["actions"]
        print ">> Byte Count"
        print stat["byte_count"]
        entry = entry + 1
            

def check_switch_connectivity():
    count = 0
    print "Checking switch connectivity:"
    for con in core.openflow._connections.values():
        print "Switch", con, "is alive"
        count = count + 1
    print switch_count - count, "device(s) unaccounted for"
    return count == switch_count

def start_spanning_tree():
    global yet_to_do
    if yet_to_do:
        print "Searching for forwarding loops with spanning tree..."
        #pox.openflow.discovery
        discov.launch()
        #pox.openflow.spanning_tree --no-flood --hold-down
        spanning_tree.launch()
        yet_to_do = False

# Get timestamp in format of HH:MM:SS = 23:13:20
def timestamp():
  stamp = time.time() # see if i have to set the locale on the time so that it doesnt confuese norwegian and english
  return datetime.datetime.fromtimestamp(stamp).strftime('%a %H:%M:%S')

def decider(bool_val, packet):
  global layer1_correct
  global last_packet

  if bool_val:
    last_packet = packet
    print "### Stage 2: Started ###"
    print "Question A: No, Policy does not match actual behaviour"
    print "Searching Question B: 'Does policy match device state?'"
    layer1_correct = False
    # Seatch deeper on device state (Layer 2)
    #start_spanning_tree()
    con_check = check_switch_connectivity()
    
    # Request flow stats (Layer 3 Question D)
    if con_check: # if Yes on question B
        print "### Stage 3: Started ###"
        print "Question B: Yes, Device state matches Policy."
        print "Searching  Question D: 'Does device state match hardware?'"
        for con in core.openflow._connections.values():
            print "Requesting flow table entries from device", con
            con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    else:
        print "### Stage 3: Started"
        print "Question B: No, Device state doesn't match Policy."
        print "Searching  Question C: 'Does physical view  match Device State?'"


############################
# Different packet handling:
############################
def handle_arp(dev_id,packet):
  arp_packet = packet.payload
  hwsrc = arp_packet.hwsrc
  hwdst = arp_packet.hwdst
  opcode = arp_packet.opcode
  if opcode == 1:
    opcode = "1:REQUEST"
  elif opcode == 2:
    opcode = "2:REPLY"
  elif opcode == 3:
    opcode = "3:REV_REQUEST"
  elif opcode == 4:
    opcode = "4:REV_REPLY"
  else:
    opcode = "x:UNSET"
  #log.info("%s DevID: %s ARP: pkt %s > %s, hw %s > %s: %s", timestamp(), dev_id, packet.src, packet.dst, hwsrc, hwdst, opcode)
  x =  "%s DevID: %s ARP: pkt %s > %s, hw %s > %s: %s" % (timestamp(), dev_id, packet.src, packet.dst, hwsrc, hwdst, opcode)
  if layer1_correct:
    print x
    if checker:
        checker.check_if_legal(x)

#######################
# Handle the ip packets
#######################

def handle_icmp(dev_id, packet, ip_packet, srcip, dstip):
  icmp_packet = ip_packet.payload
  ping_type = icmp_packet.type
  ping_code = icmp_packet.code
  ping_csum = icmp_packet.csum
  if ping_type == 0:
    ping_type = "0:ECHO_REPY"
  elif ping_type == 3:
    ping_type = "3:DEST_UNREACH"
  elif ping_type == 4:
    ping_type = "4:SRC_QUENCH"
  elif ping_type == 5:
    ping_type = "5:REDIRECT"
  elif ping_type == 8:
    ping_type = "8:ECHO_REQUEST"
  elif ping_type == 11:
    ping_type = "11:TIME_EXCEED"
  else:
    pass
  #log.info("%s DevID: %s ICMP: pkt %s > %s, ip %s > %s: %s", timestamp(), dev_id, packet.src, packet.dst, srcip, dstip, ping_type)
  x =  "%s DevID: %s ICMP: pkt %s > %s, ip %s > %s: %s" % (timestamp(), dev_id, packet.src, packet.dst, srcip, dstip, ping_type)
  if layer1_correct:
    print x
    if checker:
        violation = checker.check_if_legal(x)
        decider(violation, x)

def handle_tcp(dev_id, packet, ip_packet, srcip, dstip):
  tcp = ip_packet.payload
  srcport = tcp.srcport
  dstport = tcp.dstport
  seq = tcp.seq
  ack = tcp.ack
  flags = tcp.flags
  x =  "%s DevID: %s TCP: pkt %s > %s, ip %s > %s: srcp %s dstp %s, seq %s, ack %s, flags %s" % (timestamp(), dev_id, packet.src, packet.dst, 
                                                                                                  srcip, dstip, srcport, dstport, seq, ack, flags)
  if layer1_correct:
    print x
    if checker:
        violation = checker.check_if_legal(x)
        decider(violation, x)

def handle_udp(dev_id, packet, ip_packet, srcip, dstip):
  udp  = ip_packet.payload
  srcport = udp.srcport
  dstport = udp.dstport
  x =  "%s DevID: %s UDP: pkt %s > %s, ip %s > %s: srcp %s dstp %s" % (timestamp(), dev_id, packet.src, packet.dst,
                                                                        srcip, dstip, srcport, dstport)
  if layer1_correct:
    print x
    if checker:
        violation = checker.check_if_legal(x)
        decider(violation, x)

def handle_ip(dev_id,port,packet):
  ip_packet = packet.payload
  srcip = ip_packet.srcip
  dstip = ip_packet.dstip

  add_host(dev_id, port, srcip)

  if ip_packet.find("icmp"):
    handle_icmp(dev_id, packet, ip_packet, srcip, dstip)
  elif ip_packet.find("tcp"):
    handle_tcp(dev_id, packet, ip_packet, srcip, dstip)
  elif ip_packet.find("udp"):
    handle_udp(dev_id, packet, ip_packet, srcip, dstip)


def _handle_PacketIn(event):
  global count
  packet = event.parsed
  if packet.find("arp"):
    handle_arp(dpid_to_str(event.dpid),packet)
  elif packet.find("ipv4"):
    handle_ip(dpid_to_str(event.dpid),event.port,packet)
  else:
    log.info("UNKNOWN packet %s", packet.src)

  count = count + 1
  if count == 5: # every 5 packets recevied check data stats/small number for testing
    send_requests()
    count  = 0

def send_requests():
    for con in core.openflow._connections.values():
        con.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

def launch (switch = "", mode= ""):
  global checker
  global switch_count
  print "Number of switches expected:", switch
  switch_count = int(switch)
  start_spanning_tree()
  if "2" in mode or "3" in mode:
      checker = vc.Violation_Checker(switch, mode)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  core.openflow.addListenerByName("PortStatsReceived", handle_port_stats)
  core.openflow.addListenerByName("FlowStatsReceived", handle_flow_requests)
  print "### Stage 1: Started ###"
  print "Searching Question A: 'Does policy match actual behaviour?'"
