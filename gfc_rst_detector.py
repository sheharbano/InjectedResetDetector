#!/usr/bin/env python

## Script to detect RST injected by GFC
## <<by Sheharbano Khattak>>
## <<Sheharbano.Khattak@cl.cam.ac.uk>>
##
## Usage: python gfc_rst_detector.py <pcapfile>
## Output: Information about injected RST packets in the 
##           following format: 
##           timestamp\tconn_tuple\tseq_num
##         PRINTED TO SCREEN--REDIRECT TO WRITE TO FILE	   
##
## Based on N. Weaver, R. Sommer, and V. Paxson, "Detecting forged TCP reset
## 	packets," in Proceedings of the Network and Distributed System Security
## 	Symposium, NDSS 2009, San Diego, California, USA. The Internet
## 	Society, 2009.
##
## Implementation of the detection parameter RST SEQ CHANGE
##  from the paper above (for more details, refer to Appendix A and Table 3
##  in the paper), described as: 
##  "By quickly sending multiple
##  RSTs with increasing sequence numbers, an injector
##  can increase the likelihood of getting at least one of
##  them through. It however faces the dilemma of hav-
##  ing to pick a higher sequence number without knowing
##  what the source will sent, and therefore might guess a
##  value higher than the maximum sequence number the
##  receiver will have seen at the time the RST arrives.
##  The RST SEQ CHANGE detector leverages this obser-
##  vation by looking for back-to-pack pairs of RSTs in
##  which the second RST has a sequence number higher
##  than the first, and that exceeds the current maximum
##  sequence number. A standard compliant TCP stack
##  should never send such a packet because its RSTs
##  should either be in sequence with the data (so at the
##  maximum sequence number) or in response to packets
##  from the other side (which should have an ACK field
##  less than the maximum sequence number sent)."

#!/usr/bin/env python

import pdb
import sys

from pprint import pprint
from scapy.all import *
from collections import deque

class Pkt():
    def __init__(self, ts, seq, ack):
        self.ts = ts
        self.seq = seq
        self.ack = ack

# For each connection, key = (ip.src, tcp.sport, ip.dst, tcp.dport),
# we maintain a ConnVal object 
class ConnVal():
    def __init__(self):
	# Last 10 non-reset pkts info
        self.pkts = deque(maxlen=10)
	# Last 5 FIN packet timestamps
	self.ts_FINs = deque(maxlen=5)
	# Last 5 RST packet timestamps
	self.ts_RSTs = deque(maxlen=5)
	# status_flag is an internal control flag
	# with special meanings for different values:
	# 0 means seen no reset packet so far
        # 1 means one reset packet seen
	# If status_flag is 1, and another RST packet is seen; this will
	#   kick start injected reset detection, as it
	#   operates on consecutive reset packets 
	self.status_flag = 0
	# Two consecutive reset packets
	self.rst1 = Pkt(0.0,0,0)
	self.rst2 = Pkt(0.0,0,0)

class RSTInjectionDetector(object):
  def __init__(self, pcapfile):
    self.pcapfile = pcapfile
    # A dictionary with key = (ip.src, tcp.sport, ip.dst, tcp.dport),
    # with instance of class:ConnVal for yield
    self.conns = {}

  def process(self):
    print "#timestamp\\tconn_tuple\\tseq_num"
    reader = PcapReader(self.pcapfile)

    for packet in reader:
      if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet.getlayer(TCP)
        flags = packet.sprintf("{TCP:%TCP.flags%}")
       	ip = packet.getlayer(IP)
        ts = packet.time

        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        rev_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
	
	if not (key in self.conns):
		self.conns[key] = ConnVal()		 

	conn_val = self.conns[key]

	# If it's a FIN packet
	if "F" in flags:
		conn_val.ts_FINs.append(ts)
	# It's not a reset packet
	elif  not ("R" in flags) and ("S" in flags or "A" in flags):
		conn_val.pkts.append(Pkt(ts,tcp.seq,tcp.ack))
	# It's a reset packet
	elif "R" in flags:
		conn_val.ts_RSTs.append(ts)
		# First reset packet seen. Executed only for the first
		#    reset packet in the entire trace. For the rest of the 
		#    trace, status_flag stays 1 and hence this part is not 
		#    triggered
		if conn_val.status_flag == 0:
			conn_val.rst1 = Pkt(ts,tcp.seq,tcp.ack)
			conn_val.status_flag = 1 		

		# Second reset packet seen
		elif conn_val.status_flag == 1:
			conn_val.rst2 = Pkt(ts,tcp.seq,tcp.ack)
			# DEBUG
			# print "========================================";
			# print 'reset seen at {0}'.format(ts);
			# If no packets have been seen in the opposite direction,
			#    do not proceed, otherwise get the reverse connection 
			proceed = False
			rev_conn_val = ConnVal()
			if rev_key in self.conns:
				rev_conn_val = self.conns[rev_key]
				proceed = True

			if proceed:
				# Start: Injected RST detection logic
				cond1 = conn_val.rst2.seq > (conn_val.rst1.seq+2)

				# The two reset packets are less than 2 seconds apart
				cond2 = (conn_val.rst2.ts - conn_val.rst1.ts) < 2.0
			
				# The seq number of second reset packet is greater than the seq
				#    number of all other packets in this direction seen before the 
				#    first reset pkt
				cond3 = False
				max_seq = self.get_max(conn_val.pkts,"seq",conn_val.rst1.ts)
				if not( max_seq == -1 ) and (conn_val.rst2.seq > max_seq):
					cond3 = True

				# The seq number of second reset packet is greater than the ack
				#    number of all other packets in opposite direction seen before the 
				#    first reset pkt
				cond4 = False
				max_rev_ack = self.get_max(rev_conn_val.pkts,"ack",conn_val.rst1.ts)
				if not( max_rev_ack == -1 ) and (conn_val.rst2.seq > (max_rev_ack + 2)):
					cond4 = True

				# No FIN packet seen in either direction seen prior to the first 
				#    reset packet
				max_FIN_ts = self.get_max(conn_val.ts_FINs,"ts",conn_val.rst1.ts)
				cond5 = (max_FIN_ts==-1)

				# No RST packet seen in opposite direction seen prior to the first 
				#    reset packet
				max_rev_RST_ts = self.get_max(rev_conn_val.ts_FINs,"ts",conn_val.rst1.ts)
				cond6 = (max_rev_RST_ts==-1)
 
				# DEBUG
				#print 'cond1:{0},cond2:{1},cond3:{2},cond4:{3},cond5:{4},cond6:{5}'.format(cond1,cond2,cond3,cond4,cond5,cond6);

				if cond1 and cond2 and cond3 and cond4 and cond5 and cond6: 	
					print '{0}\t{1}\t{2}'.format(conn_val.rst2.ts,key,conn_val.rst2.seq)
			
			# Whether the second reset was detected as injected or not,
			#    it now serves as the first reset packet for subsequent analysis.
			#    (a sliding window type of concept)
			conn_val.rst1 = conn_val.rst2
			conn_val.rst2 = Pkt(0.0,0,0) 		

  def get_max(self,q,to_sort_on,current_ts):
    if to_sort_on == "seq":
	q_sorted = sorted(q,key=lambda pkt: pkt.seq)
	for pkt in reversed(q_sorted):
		if pkt.ts < current_ts:
			return pkt.seq

    elif to_sort_on == "ack":
	q_sorted = sorted(q,key=lambda pkt: pkt.ack)
	for pkt in reversed(q_sorted):
		if pkt.ts < current_ts:
			return pkt.ack

    elif to_sort_on == "ts":
	q_sorted = sorted(q)
	for ts in reversed(q_sorted):
		# !!Note: As per the original paper, the expression should be
		#   (ts < current_ts). However, Scapy rounds off the decimal part 
		#   of the timestamp to 2 digits, essentially making two slightly
		#   differing timestamps equal. To deal with this problem, I do <=
		if ts <= current_ts:
			return ts

    return -1
    


if __name__ == "__main__":
  if len(sys.argv) < 2:
    print "usage: %s pcapfile" % (sys.argv[0])
    sys.exit(1)

  detector = RSTInjectionDetector(sys.argv[1])
  detector.process()

