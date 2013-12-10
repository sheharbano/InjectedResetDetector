 Script to detect RST injected by GFC
 <<by Sheharbano Khattak>>
 <<Sheharbano.Khattak@cl.cam.ac.uk>>

 Usage: python gfc_rst_detector.py <pcapfile>
 Output: Information about injected RST packets in the 
           following format: 
           timestamp\tconn_tuple\tseq_num
         PRINTED TO SCREEN--REDIRECT TO WRITE TO FILE	   

 Based on N. Weaver, R. Sommer, and V. Paxson, "Detecting forged TCP reset
 	packets," in Proceedings of the Network and Distributed System Security
 	Symposium, NDSS 2009, San Diego, California, USA. The Internet
 	Society, 2009.

 Implementation of the detection parameter RST SEQ CHANGE
  from the paper above (for more details, refer to Appendix A and Table 3
  in the paper), described as: 
  "By quickly sending multiple
  RSTs with increasing sequence numbers, an injector
  can increase the likelihood of getting at least one of
  them through. It however faces the dilemma of hav-
  ing to pick a higher sequence number without knowing
  what the source will sent, and therefore might guess a
  value higher than the maximum sequence number the
  receiver will have seen at the time the RST arrives.
  The RST SEQ CHANGE detector leverages this obser-
  vation by looking for back-to-pack pairs of RSTs in
  which the second RST has a sequence number higher
  than the first, and that exceeds the current maximum
  sequence number. A standard compliant TCP stack
  should never send such a packet because its RSTs
  should either be in sequence with the data (so at the
  maximum sequence number) or in response to packets
  from the other side (which should have an ACK field
  less than the maximum sequence number sent)."
