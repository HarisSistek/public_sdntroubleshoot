# Checks if packets violate the network policy
# @ Author Haris Sistek
import os
import re
import time, datetime
import automator as auto

class Violation_Checker(object):
  '''
  Interpret all possible options given by a rule add the to a dict
  Returns a dict with option variables, or None if no options are found
  '''
  def interpret_options(self, rule):
    match = re.search(r'sport\s+(?P<sport>.+)\s+dport\s+(?P<dport>.+)', rule)
    if match:
      return match.groupdict()
    else:
      just_sport_match = re.search(r'sport\s+(?P<sport>.+)', rule)
      if just_sport_match:
         return just_sport_match.groupdict()
      else:
        just_dport_match = re.search(r'dport\s+(?P<dport>.+)', rule)
      if just_dport_match:
         return just_dport_match.groupdict()
      else:
        return None
  
  '''
  Use to merge the rule dicts that are extracted from the rules.
  prot = dict with the protocol name
  type_dict = values extracted from Time, Date or Vlan rules
  options = values extracted from "interpret_options"
  '''
  def merge_dicts(self,prot,type_dict,options):
    ret_dict = {}
    if options:
      ret_dict = dict(list(prot.items()) + list(type_dict.items()) + list(options.items()))
    else:
      ret_dict = dict(list(prot.items()) + list(type_dict.items()))
    return ret_dict
    

  '''
  Extract all data needed to interpet "Data" rules, returns dict of the data stored
  '''
  def interpret_data_rule(self,prot,rule):
    ret_dict = {}
    ret_dict["rule_type"] = "Data"
    ret_dict["rule_string"] = rule
    ret_dict["lim"] = rule # just simple search later, easier the to split up the line atm
    match = re.search(r'^Data\s+(?P<lim>.+)\s+(?P<notation>.+)\s+from\s+(?P<from>.+)',rule)
    if match:
      ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
      return self.merge_dicts(prot, ret_dict, {})
    else:
      match = re.search(r'^Data\s+(?P<lim>.+)\s+(?P<notation>.+)\s+to\s+(?P<to>.+)',rule)
      if match:
        ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
        return self.merge_dicts(prot, ret_dict, {})
      else:
        return None

  '''
  Helps us convert the policy data size notation into bytes, because this is what
  openflow port stat request is returning
  '''
  def convert_notation_to_bytes(self, lim, notation):
    notation = notation.upper()
    if notation == "B":
        return int(lim)
    elif notation == "KB":
        return int(lim) * 1024
    elif notation == "MB":
        return int(lim) * 1024 * 1024
    elif notation == "GB":
        return int(lim) * 1024 * 1024 * 1024
    elif notation == "TB":
        return int(lim) * 1024 * 1024 * 1024 * 1024
    else:
        return 0

  '''
  Extract all the data needed from "Time" rule, return a dict of that data
  '''
  def interpret_time_rule(self,prot,rule):
    ret_dict = {}
    ret_dict["rule_type"] = "Time"
    ret_dict["rule_string"] = rule
    match = re.search(r'^Time\s+(?P<start_time>.+)\s+to\s+(?P<end_time>.+)\s+block\s+(?P<from>.+)\s+to\s+(?P<to>\S+)\s+', rule)
    if match:
      print "match1"
      options = self.interpret_options(rule)
      ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
      return self.merge_dicts(prot, ret_dict, options)
    else:
      match = re.search(r'^Time\s+(?P<start_time>.+)\s+to\s+(?P<end_time>.+)\s+block\s+(?P<from>\S+)\s+', rule)
      if match:
        options = self.interpret_options(rule)
        ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
        return self.merge_dicts(prot, ret_dict, options)
      else:
        return None

  '''
  Extract all the data from "Date" rule, return a dict of that data
  '''
  def interpret_date_rule(self,prot,rule):
    ret_dict = {}
    ret_dict["rule_type"] = "Date"
    ret_dict["rule_string"] = rule
    match = re.search(r'^Date\s+(?P<start_date>.+)\s+to\s+(?P<end_date>.+)\s+block\s+(?P<from>.+)\s+to\s+(?P<to>\S+)\s+', rule)
    if match:
      options = self.interpret_options(rule)
      ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
      return self.merge_dicts(prot, ret_dict, options)
    else:
      match = re.search(r'^Date\s+(?P<start_date>.+)\s+to\s+(?P<end_date>.+)\s+block\s+(?P<from>\S+)', rule)
      if match:
        options = self.interpret_options(rule)
        ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
        return self.merge_dicts(prot, ret_dict, options)
      else: # specidic calander date:
        match = re.search(r'^Date\s+(?P<start_date>.+)\s+block\s+(?P<from>\S+)\s+to\s+(?P<to>\S+)\s+', rule)
        if match:
          options = self.interpret_options(rule)
          ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
          return self.merge_dicts(prot, ret_dict, options)
        else:
           match = re.search(r'^Date\s+(?P<start_date>.+)\s+block\s+(?P<from>\S+)', rule)
           if match:
             options = self.interpret_options(rule)
             ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
             return self.merge_dicts(prot, ret_dict, options)
           else:
             return None
      
  '''
  Extract all the data from "Vlan" rule, return a dict of that data
  '''
  def interpret_vlan_rule(self,prot,rule):
    ret_dict = {}
    ret_dict["rule_type"] = "VLAN"
    ret_dict["rule_string"] = rule
    ret_dict["hosts"] = rule # just simple search later, easier the to split up the line atm
    match = re.search(r'^Vlan\s+(?P<vlan_id>.+)\s+has',rule)
    if match:
      ret_dict = dict(list(ret_dict.items()) + list(match.groupdict().items()))
      return self.merge_dicts(prot, ret_dict, {})
    else:
      return None
    
  '''
  Decide what kind of rule (Date, Time or Vlan) and send to appropriate subfuntion
  '''
  def interpret_primitive(self, prot, rule):
    if "Time" in rule:
      return self.interpret_time_rule(prot,rule)
    elif "Date" in rule:
      return self.interpret_date_rule(prot,rule)
    elif "Vlan" in rule:
      return self.interpret_vlan_rule(prot,rule)
    elif "Data" in rule:
      return self.interpret_data_rule(prot,rule)
    else:
      pass

  '''
  This rule will return all the date from a rule by using the subfunctions above.
  Its main task is to decide what protocol the rule is talking about, if non
  is specified just assume TCP, UDP and ICMP is what the user wants.
  '''
  def interpret_block_and_options(self, rule):
    prot = {}
    if "prot TCP" in rule:
      prot["prot"] = "TCP"
      return self.interpret_primitive(prot, rule)
    elif "prot UDP" in rule:
      prot["prot"] = "UDP"
      return self.interpret_primitive(prot, rule)
    elif "prot ARP" in rule:
      prot["prot"] = "ACK"
      return self.interpret_primitive(prot, rule)
    elif "prot ICMP" in rule:
      prot["prot"] = "ICMP"
      return self.interpret_primitive(prot, rule)
    elif "Vlan" in rule:
      prot["prot"] = "VLAN"
      return self.interpret_primitive(prot, rule)
    elif "Data" in rule:
      prot["prot"] = "Data"
      return self.interpret_primitive(prot, rule)
    else:
      prot["prot"] = "TCP/UDP/ICMP"
      return self.interpret_primitive(prot, rule)

  '''
  Reads all the policy files, extracts the policy varaibles
  '''
  def read_policy_folder(self, policy_path):
    for file in os.listdir(policy_path):
      if file.endswith(".pol"):
        with open(os.path.join(policy_path,file)) as f:
          lines = f.readlines()
          for line in lines:
            if re.match(r'^.+\s+=\s+.+',line): # interpret hosts
              match =  re.match(r'^(.+)\s+=\s+(.+)',line)
              self.policy_hosts_ip[match.group(2)] =  match.group(1)
              self.policy_hosts_name[match.group(1)] =  match.group(2)
            elif re.match(r'^Date',line) or re.match(r'Time',line)  or re.match(r'^Vlan',line) or re.match(r'^Data',line):
              self.policy_rules.append(line)
              self.policy_rules_values.append(self.interpret_block_and_options(line))

  '''
  Rules can contain a "*" which specifies "any". Example srcip * would mean match rule with any source ip
  '''
  def check_two_values(self, rule_val, packet_val):
    if rule_val == "*" or rule_val == None:
      return True
    else:
      return rule_val == packet_val
  
  '''
  Compares rule src and dst against packet src and dst
  Returns a boolean value
  '''
  def check_rule_and_packet(self, r_src, p_src, r_dst,  p_dst):
    ret1 =  self.check_two_values(r_src, p_src)
    ret2 =  self.check_two_values(r_dst, p_dst)
    if ret1 and ret2:
      return ret1 and ret2
    else:
      ret1 =  self.check_two_values(r_dst, p_src)
      ret2 =  self.check_two_values(r_src, p_dst)
    return ret1 and ret2
  
  def check_ports(self, r_sport, p_sport, r_dport, p_dport):
    ret1 = self.check_two_values(r_sport, p_sport)
    ret2 = self.check_two_values(r_dport, p_dport)
    return ret1 and ret2

  '''
  Finally checks if packet violates a rule by looking at the primitive (time,date,vlan)
  Returns True if there is a violation, false if not
  '''
  def check_time_or_date(self, rule, packet, packet_string):
    match = re.search(r'^(?P<date>\S+)\s+(?P<time>\S+)\s+', packet_string) # extract date and time from packet timestamp
    if rule["rule_type"] == "Time":
      if match:
        mdict = match.groupdict()
        packet_time = time.strptime(mdict.get("time"),"%H:%M:%S") # test this
        rule_start_time = time.strptime(rule.get("start_time"),"%H:%M") # test this
        rule_end_time = time.strptime(rule.get("end_time"),"%H:%M") # test this
        
        if packet_time >= rule_start_time and packet_time <= rule_end_time:
          return True
        else:
          return False
    elif rule["rule_type"] == "Date":
      if match:
        mdict = match.groupdict()
        packet_date = time.strptime(mdict.get("date"),"%a") # test this
        rule_start_date = time.strptime(rule.get("start_date"),"%a") # test this
        rule_end_date = time.strptime(rule.get("end_date"),"%a") # test this
        
        if packet_date  >= rule_start_date and packet_date <= rule_end_date:
          return True
        else:
          return False
    else:
      print "vlan"
    
  '''
  Main method for checking icmp packets, extract rule src and dst, packet src and dst, check if it there is match
  forward matching rule and packet to next method so to check if values match on other parameters. 
  Lastly print out violation if any and return a boolean value. True if a violation, false if not. 
  '''
  def check_icmp(self, packet_dict, packet_string):
    for rule_dict in self.policy_rules_values:
      if "ICMP" in rule_dict["prot"]: # rule may miss these keys, therefor use get -> will return None if key is non existent
        r_src = None # at some point rules contains IPs and not host names
        r_dst = None
        match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("from"))
        if match:
          r_src = rule_dict.get("from")
        else:
          r_src = self.policy_hosts_name.get(rule_dict.get("from"))
        if rule_dict.get("to"):
          match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("to"))
          if match:
            r_dst = rule_dict.get("to")
          else:
            r_dst = self.policy_hosts_name.get(rule_dict.get("to"))
        
        if self.check_rule_and_packet(r_src, 
                                      packet_dict["ipsrc"], r_dst, packet_dict["ipdst"]):
          
          ret = self.check_time_or_date(rule_dict, packet_dict, packet_string)
          
          if ret:
            return rule_dict["rule_string"]

  def check_udp(self, packet_dict, packet_string):
    for rule_dict in self.policy_rules_values:
      if "UDP" in rule_dict["prot"]: # rule may miss these keys, therefor use get -> will return None if key is non existent
        r_src = None 
        r_dst = None
        match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("from"))
        if match:
          r_src = rule_dict.get("from")
        else:
          r_src = self.policy_hosts_name.get(rule_dict.get("from"))
        if rule_dict.get("to"):
          match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("to"))
          if match:
            r_dst = rule_dict.get("to")
          else:
            r_dst = self.policy_hosts_name.get(rule_dict.get("to"))
        
        if self.check_rule_and_packet(r_src, 
                                      packet_dict["ipsrc"], r_dst, packet_dict["ipdst"]):
          
          if self.check_ports(rule_dict.get("sport"),
                              packet_dict["src_port"], rule_dict.get("dport"), packet_dict["dst_port"]):
            
            ret = self.check_time_or_date(rule_dict, packet_dict, packet_string)
            
            if ret:
              return rule_dict["rule_string"]

  def check_tcp(self, packet_dict, packet_string):
    for rule_dict in self.policy_rules_values:
      if "TCP" in rule_dict["prot"]: # rule may miss these keys, therefor use get -> will return None if key is non existent
        r_src = None
        r_dst = None
        match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("from"))
        if match:
          r_src = rule_dict.get("from")
        else:
          r_src = self.policy_hosts_name.get(rule_dict.get("from"))
        if rule_dict.get("to"):
          match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule_dict.get("to"))
          if match:
            r_dst = rule_dict.get("to")
          else:
            r_dst = self.policy_hosts_name.get(rule_dict.get("to"))
        
        if self.check_rule_and_packet(r_src,
                                      packet_dict["ipsrc"], r_dst, packet_dict["ipdst"]):
          
          if self.check_ports(rule_dict.get("sport"),
                              packet_dict["src_port"], rule_dict.get("dport"), packet_dict["dst_port"]):
            
            ret = self.check_time_or_date(rule_dict, packet_dict, packet_string)
            
            if ret:
              return rule_dict["rule_string"]


  def check_for_violation(self, packet_dict):
    for vpacket in self.v_packets: # for violating packet in violation list
      if vpacket["prot"] == packet_dict["prot"]:
        if vpacket["devID"] == packet_dict["devID"]: # packet reply on same device
          if vpacket["ipsrc"] == packet_dict["ipdst"] and vpacket["ipdst"] == packet_dict["ipsrc"]: # is it a reply
            if vpacket["prot"] == "ICMP":
              if "8" in vpacket["ping_type"] and "0" in packet_dict["ping_type"]: # ping type is a reply
                print "## Policy Violation Found: PACKET RETURN ##"
                print "> Packet:", vpacket["packet_string"]
                print "> Packet:", packet_dict["packet_string"]
                print "  violates:  "
                print "> Rule:", vpacket["rule_string"]
                if vpacket in self.v_packets:
                  self.v_packets.remove(vpacket)
                if packet_dict in self.v_packets:
                  self.v_packets.remove(packet_dict)
                return True
            else:
              if vpacket["dst_port"] == packet_dict["src_port"] and vpacket["src_port"] == packet_dict["dst_port"]:
                print "## Policy Violation Found: PACKET RETURN ##"
                print "> Packet:", vpacket["packet_string"]
                print "> Packet:", packet_dict["packet_string"]
                print "  violates:  "
                print "> Rule:", vpacket["rule_string"]
                if vpacket in self.v_packets:
                  self.v_packets.remove(vpacket)
                if packet_dict in self.v_packets:
                  self.v_packets.remove(packet_dict)
                return True
        else: # packet is on another device
          if vpacket["ipsrc"] == packet_dict["ipsrc"] and vpacket["ipdst"] == packet_dict["ipdst"]: # packet has been forwarded
            if vpacket["prot"] == "ICMP":
              if vpacket["ping_type"] == packet_dict["ping_type"]: # ping type is a reply of another
                print "## Policy Violation Found: PACKET FORWARDING ##"
                print "> Packet:", vpacket["packet_string"]
                print "> Packet:", packet_dict["packet_string"]
                print "  violates:  "
                print "> Rule:", vpacket["rule_string"]
                if vpacket in self.v_packets:
                  self.v_packets.remove(vpacket)
                if packet_dict in self.v_packets:
                  self.v_packets.remove(packet_dict)
                return True
            else:
              if vpacket["dst_port"] == packet_dict["dst_port"] and vpacket["src_port"] == packet_dict["src_port"]:
                print "## Policy Violation Found: PACKET FORWARDING ##"
                print "> Packet:", vpacket["packet_string"]
                print "> Packet:", packet_dict["packet_string"]
                print "  violates:  "
                print "> Rule:", vpacket["rule_string"]
                if vpacket in self.v_packets:
                  self.v_packets.remove(vpacket)
                if packet_dict in self.v_packets:
                  self.v_packets.remove(packet_dict)
                return True
    return False

  '''
  Recieves a string from the sdn_dump, check against policy and return boolean value    
  True, if approved
  False, if there is a policy violation
  '''
  def check_if_legal(self,dump_string):
    #print dump_string # should check this string for error flags
    if "ICMP" in dump_string:
      match = re.match(r'^.+\s+DevID:\s+(?P<devID>.+)\s+(?P<prot>.+):\s+pkt\s+(?P<pktsrc>.+)\s+>\s+(?P<pktdst>.+),\s+ip\s+(?P<ipsrc>.+)\s+>\s+(?P<ipdst>.+):\s+(?P<ping_type>.+)',dump_string)
      match_dict =  match.groupdict()
      #print match_dict
      #print match_dict
      violation = self.check_icmp(match_dict,dump_string)
      if violation:
        string_dict = {}
        string_dict["packet_string"] = dump_string
        rule_dict = {}
        rule_dict["rule_string"] = violation
        res_dict = self.merge_dicts(match_dict,string_dict, rule_dict)
        self.v_packets.append(res_dict)
        if self.check_for_violation(res_dict):
          return True
      return False
      # now match them somehow
    elif "UDP" in dump_string:
      match = re.match(r'^.+\s+DevID:\s+(?P<devID>.+)\s+(?P<prot>.+):\s+pkt\s+(?P<pktsrc>.+)\s+>\s+(?P<pktdst>.+),\s+ip\s+(?P<ipsrc>.+)\s+>\s+(?P<ipdst>.+):\s+srcp\s+(?P<src_port>.+)\s+dstp\s+(?P<dst_port>.+)',dump_string)
      match_dict =  match.groupdict()
      #print match_dict
      violation = self.check_udp(match_dict,dump_string)
      if violation:
        string_dict = {}
        string_dict["packet_string"] = dump_string
        rule_dict = {}
        rule_dict["rule_string"] = violation
        res_dict = self.merge_dicts(match_dict,string_dict, rule_dict)
        self.v_packets.append(res_dict)
        if self.check_for_violation(res_dict):
          return True
      return False
    elif "ARP" in dump_string: # ask if this will be needed, is nice to have for now
      match = re.match(r'^.+ARP:\s+pkt\s+(?P<pktsrc>.+)\s+>\s+(?P<pktdst>.+),\s+hw\s+(?P<hwsrc>.+)\s+>\s+(?P<hwdst>.+):\s+(?P<arp_type>.+)',dump_string)
      match_dict =  match.groupdict()
      #print match_dict
    elif "TCP" in dump_string:
      match = re.match(r'^.+\s+DevID:\s+(?P<devID>.+)\s+(?P<prot>.+):\s+pkt\s+(?P<pktsrc>.+)\s+>\s+(?P<pktdst>.+),\s+ip\s+(?P<ipsrc>.+)\s+>\s+(?P<ipdst>.+):\s+srcp\s+(?P<src_port>.+)\s+dstp\s+(?P<dst_port>.+),\s+seq (?P<seq>.+),\s+ack\s+(?P<ack>.+)\s+flags\s+(?P<flags>.+)',dump_string)
      match_dict =  match.groupdict()
      #print match_dict
      violation = self.check_tcp(match_dict,dump_string)
      if violation:
        string_dict = {}
        string_dict["packet_string"] = dump_string
        rule_dict = {}
        rule_dict["rule_string"] = violation
        res_dict = self.merge_dicts(match_dict,string_dict, rule_dict)
        self.v_packets.append(res_dict)
        if self.check_for_violation(res_dict):
          return True
      return False

  def check_if_ports_legal(self, bsent, brecv, psent, precv):
    rule_ip = None
    for rule in self.policy_rules_values:
      if "Data" in rule["rule_type"]:
        if "to" in rule: # what the IP  can recv
          match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule.get("to"))
          if match:
            rule_ip = rule.get("to")
          else:
            rule_ip = self.policy_hosts_name.get(rule.get("to"))
          # We now know the rule IP, lets match it agaisnt actual port stats
          for recv_stat in brecv:
            if recv_stat == rule_ip:
              rule_bytes = self.convert_notation_to_bytes(rule.get("lim"), rule.get("notation"))
              if int(rule_bytes) < int(brecv[recv_stat]):
                 print "## Policy Violation Found: RECEIVED TO MUCH DATA ##"
                 print "> IP:", rule_ip, "address received:",  int(brecv[recv_stat]), "bytes"
                 print "> IP:", rule_ip, "can only receive:", int(rule_bytes), "bytes"
                 print "  violates:   " 
                 print "> Rule:", rule.get("rule_string")
                 return True
        elif "from" in rule: # what the IP can send
          match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule.get("from"))
          if match:
            rule_ip = rule.get("from")
          else:
            rule_ip = self.policy_hosts_name.get(rule.get("from"))
          # We now know the rule IP, lets match it agaisnt actual port stats
          for recv_stat in brecv:
            if recv_stat == rule_ip:
              rule_bytes = self.convert_notation_to_bytes(rule.get("lim"), rule.get("notation"))
              if int(rule_bytes) < int(brecv[recv_stat]):
                 print "## Policy Violation Found: SENDING TO MUCH DATA ##"
                 print "> IP:", rule_ip, "address sent:",  int(brecv[recv_stat]), "bytes"
                 print "> IP:", rule_ip, "can only send:", int(rule_bytes), "bytes"
                 print "  violates:   "
                 print "> Rule:", rule.get("rule_string")
                 return True
        else:
          pass
    return False

  def __init__(self,switch, mode):
    self.policy_hosts_ip = {}
    self.policy_hosts_name = {}
    self.policy_rules = []
    self.policy_rules_values = []
    self.v_packets = []
    self.read_policy_folder(os.path.dirname(os.path.realpath(__file__)) + "/policies")
    if "3" in mode:
      automator = auto.Automator(self.policy_rules, self.policy_rules_values, 
                                 self.policy_hosts_ip, self.policy_hosts_name,switch)
