# Policy Syntax

## Language Primetives

Each network policy rule is starts with a case sensitive primetive.
<ol>
  <li>Time</li>
  <li>Date</li>
  <li>Vlan</li>
</ol>

In addition some of the rules contain OPTIONS:
<ol>
  <li> TCP/UDP = specify protocol </li>
  <li> sip = source ip</li>
  <li> dip = destination ip</li>
  <li> sport = source port</li>
  <li> dport = destination port</li>
</ol>

Declare hosts as to make the policy more readble.
NB! Declared host require to start with letter and not number, and have to be declared at the startof the file..

host2 = 10.0.0.1 is allowed

2host = 10.0.0.1 is **not** allowed

### Hosts
h1 = 10.0.100.1

h2 = 10.0.100.2

h3 = 10.0.100.3

### Time blocks/allows
Time 10:00 to 23:00 block 8.8.8.8          

Time 10:00 to 12:00 block h1 to h2

Time 12:00 to 12:30 block h3 prot TCP sip * dport 22

### Date blocks/allows
Date MON to FRI block h2 to h1

Date 23 DES block h1

### Vlans
Vlan 10 has h1, h2
