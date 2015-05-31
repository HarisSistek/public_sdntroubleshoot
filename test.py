import violation_checker as vc
import sys

cmd = None
x = vc.Violation_Checker()

cmd = sys.argv
print 'Commands:', sys.argv

if len(cmd) == 1:
    cmd = None

if cmd == None or "1" in cmd:
    print "######## Start ###############"
    print "File extraction tests:"
    print "hosts_ip:", x.policy_hosts_ip
    print "hosts_name:", x.policy_hosts_name
    print "rules:"
    for rule in x.policy_rules:
        print rule
    for rule in x.policy_rules_values:
        print rule

if cmd == None or "2" in cmd:
    print "############# Second row ###############"
    print "Check if legal tests"
    x.check_if_legal("Fre 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    x.check_if_legal("Fre 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: srcp 59941 dstp 5001")
    x.check_if_legal("Fre 10:17:16 DevID: 00-00-00-00-00-04 ARP: pkt 2a:a9:9a:ad:90:19 > ff:ff:ff:ff:ff:ff, hw 2a:a9:9a:ad:90:19 > 00:00:00:00:00:00: 1:REQUEST")
    x.check_if_legal("Fre 10:18:06 DevID: 00-00-00-00-00-03 TCP: pkt 26:be:49:55:aa:19 > 2a:a9:9a:ad:90:19, ip 10.0.1.101 > 10.0.1.100: srcp 5001 dstp 47727, seq 3318916247, ack 974466288, flags 18")
    x.check_if_legal("Fre 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 26:be:49:55:aa:19 > 2a:a9:9a:ad:90:19, ip 10.0.1.101 > 10.0.1.100: 0:ECHO_REPY")

if cmd == None or "3" in cmd:
    print "############# Third row ###############"
    print "Options tests:"
    print "T1", x.interpret_options("Time 12:00 to 12:30 block h3 prot TCP sport 1001 dport 22")
    print "T2", x.interpret_options("Time 12:00 to 12:30 block h3 prot TCP sport 1001")
    print "T3", x.interpret_options("Time 12:00 to 12:30 block h3 prot TCP dport 22")
    print "T4",x.interpret_options("Time 12:00 to 12:30 block h3 prot TCP sport * dport 22")

if cmd == None or "4" in cmd:
    print "############# Fourth row ###############"
    print "Intepret block and options test:"
    print "T5",x.interpret_block_and_options("Time 12:00 to 12:30 block h3 prot UDP sport * dport 2222")
    print "T6",x.interpret_block_and_options("Time 12:00 to 12:30 block h3 to h2 prot TCP sport * dport 22")
    print "T7",x.interpret_block_and_options("Time 12:00 to 12:30 block h3 to h2")
    print "T8",x.interpret_block_and_options("Time 12:00 to 12:30 block h3 to h2")
    print "T9",x.interpret_block_and_options("Date MON to FRI block h3 to h2 prot TCP sport * dport 22")
    print "T10",x.interpret_block_and_options("Date MON to FRI block h3 to h2 prot TCP sport *")
    print "T11",x.interpret_block_and_options("Date MON to FRI block h3 prot UDP dport 22")
    print "T12",x.interpret_block_and_options("Date MON to FRI block h3 to h2")
    print "T13",x.interpret_block_and_options("Date MON to FRI block h3")
    print "T14",x.interpret_block_and_options("Date MON to FRI block h2 prot UDP")
    print "T15",x.interpret_block_and_options("Vlan 10 has h1, h2")
    print "T16",x.interpret_block_and_options("Vlan 20 has h1, h3, h4, h2")

if cmd == None or "5" in cmd:
    print "T17",x.interpret_block_and_options("Date MON to FRI block h3")
    print "T18",x.interpret_block_and_options("Date 23 DES block h1")
    print "T19",x.interpret_block_and_options("Date MON to FRI block h3 prot UDP")
    print "T20",x.interpret_block_and_options("Date MON to FRI block h3 prot UDP dport 33")
    print "T21",x.interpret_block_and_options("Date 23 DES block h1 prot TCP sport 100 dport 10")

if cmd == None or "icmp" in cmd:
    print "--------------------- Both should be blocked: ONE Switch:"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.100: 0:ECHO_REPLY")
    print "--------------------- Both should be blocked:"
    x.check_if_legal("Fri 10:17:20 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    print "--------------------- Both should be blocked:"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.110: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.110 > 10.0.1.101: 0:ECHO_REPLY")
    print "--------------------- Block: TWO SWITCH"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: 0:ECHO_REPLY")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: 0:ECHO_REPLY")
    print "--------------------- Block: THREE SWITCH"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-05 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: 8:ECHO_REQUEST")

    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-05 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: 0:ECHO_REPLY")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: 0:ECHO_REPLY")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: 0:ECHO_REPLY")
    print "--------------------- Not Blocked:"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.110 > 10.0.1.102: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.110 > 10.0.1.102: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 08:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.104 > 10.0.1.111: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 08:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.104 > 10.0.1.111: 8:ECHO_REQUEST")
    print "--------------------- DONT BLOCK REPLY: REPLY ON OTHER DEVICE"
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-04 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.100: 0:ECHO_REPLY")
    print "--------------------- DONT BLOCK FORWARD: SAME PACKET ON SAME DEVICE"
    x.check_if_legal("Fri 10:17:20 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: 8:ECHO_REQUEST")
if cmd == None or "udp" in cmd:
    print "--------------------- Both should be blocked:"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.100 > 10.0.1.101: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.100: srcp 22 dstp 1000")
    print "--------------------- Both should work (time):"
    x.check_if_legal("Fri 08:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.111: srcp 1000 dstp 22")
    x.check_if_legal("Fri 08:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.111 > 10.0.1.101: srcp 1000 dstp 22")
    print "--------------------- Both should block (time):"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.101 > 10.0.1.111: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.111 > 10.0.1.101: srcp 22 dstp 1000")
    print "--------------------- Both should block (time):"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.102 > 10.0.0.3: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.3 > 10.0.1.102: srcp 22 dstp 1000")
    print "--------------------- Not block:"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.4 > 10.0.1.102: srcp 1000 dstp 22")
    print "--------------------- Block:"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.103 > 10.0.1.102: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-04 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.103 > 10.0.1.102: srcp 1000 dstp 22")
    print "--------------------- Block:"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.105 > 10.0.0.6: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.0.6 > 10.0.1.105: srcp 22 dstp 1000")
    print "--------------------- Block:"
    x.check_if_legal("Fri 10:18:21 DevID: 00-00-00-00-00-03 UDP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.106 > 10.0.0.6: srcp 1000 dstp 22")
    x.check_if_legal("Fri 10:17:16 DevID: 00-00-00-00-00-03 ICMP: pkt 2a:a9:9a:ad:90:19 > 26:be:49:55:aa:19, ip 10.0.1.106 > 10.0.0.6: 8:ECHO_REQUEST")

if cmd == None or "tcp" in cmd:
    print "--------------- block both"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.100 > 10.0.1.101: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.101 > 10.0.1.100: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "---------------- both should work:"
    x.check_if_legal("Fri 08:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.101 > 10.0.1.100: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 08:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.100 > 10.0.1.101: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- block both"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.101 > 10.0.1.111: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.111 > 10.0.1.101: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "-------------- block both"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.102 > 10.0.0.3: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.3 > 10.0.1.102: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- Not block:"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.4 > 10.0.1.102: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- Block"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.103 > 10.0.1.102: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.102 > 10.0.1.103: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- Block"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.105 > 10.0.0.6: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.6 > 10.0.1.105: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "-------------- Block"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.6 > 10.0.1.106: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- Block: TWO SWTICH:"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.100 > 10.0.1.101: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-04 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.100 > 10.0.1.101: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-04 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.101 > 10.0.1.100: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.101 > 10.0.1.100: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    print "--------------- Block: THREE SWTICH:"
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.105 > 10.0.0.6: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-04 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.105 > 10.0.0.6: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-05 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.1.105 > 10.0.0.6: srcp 1000 dstp 22, seq 1206717985, ack 0, flags 2")

    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-05 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.6 > 10.0.1.105: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-04 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.6 > 10.0.1.105: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
    x.check_if_legal("Fri 13:49:37 DevID: 00-00-00-00-00-03 TCP: pkt 2a:10:bf:e4:63:af > 42:ec:42:93:c2:44, ip 10.0.0.6 > 10.0.1.105: srcp 22 dstp 1000, seq 1206717985, ack 0, flags 2")
