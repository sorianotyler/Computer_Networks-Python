# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#
# TYler Soriano 
# CSE 150 
# Final controler

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    #print(switch_id)
    ipv4 = packet.find('ipv4')
    icmp = packet.find('icmp')
    tcp = packet.find('tcp')
    arp = packet.find('arp')

    Msg = of.ofp_flow_mod()
    #print(ipv4.srcip)
    #print(ipv4.dstip)
    #print(icmp)

    #set the time timeouts
    Msg.idleTimeout = 40 #flow entry is removed from the flow table and the hardware after 30 sec bc no packets match it
    Msg.hardTimeout = 60 #flow entry is removed from the flow table and the hardware whether or not packets match it

    def flood():
      #print("arp")
      Msg.data = packet_in
      Msg.match = of.ofp_match.from_packet(packet)
      Msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      self.connection.send(Msg)
    
    def drop():
      Msg.match = of.ofp_match.from_packet(packet)
      self.connection.send(Msg)
    
    def route(portNumber):
      Msg.data = packet_in
      Msg.match = of.ofp_match.from_packet(packet)
      out_action = of.ofp_action_output(port = portNumber) 
      Msg.actions.append(out_action)
      self.connection.send(Msg) 

    
# went to tutoring with Wil he helped me develop my sudocode which i use to complete this assignment. He recomended i create funcitons and do it this way. 
# TA hoafan helped me implementing the TCP section of the code - so that the TCP packets get routed correctly
    if arp:
      flood()
    elif ipv4:
      if tcp:
        if switch_id == 1:
          if ipv4.dstip == "10.1.1.10":
            route(8)
          elif ipv4.dstip == "10.1.2.20":
            route(9)
          else:
            route(1)
        
        elif switch_id == 2:
          if ipv4.dstip == "10.1.3.30":
            route(10)
            #print ("routed h30")
          elif ipv4.dstip == "10.1.4.40":
            route(11)
          else:
            route(1)
        
        elif switch_id == 3:
          if ipv4.dstip == "10.2.5.50":
            route(12)
            #print ("routed h50")
          elif ipv4.dstip == "10.2.6.60":
            route(13)
          else:
            route(1)

        elif switch_id == 4:
          if ipv4.dstip == "10.2.7.70":
            route(14)
          elif ipv4.dstip == "10.2.8.80":
            route(15)
          else:
            route(1)
        
        elif switch_id == 6:
          if ipv4.dstip == "10.3.9.90":
            route(16)
          else:
            route(1)
        
        elif switch_id == 5:
          #for server
          if(ipv4.dstip == "10.3.9.90"):
            if (ipv4.srcip == "108.24.31.112" or ipv4.srcip == "106.44.82.103"):
              print("in server")
              drop()
            else:
              
              route(5)
          
          #trusted host
          elif(ipv4.dstip == "108.24.31.112"):
            route(6)

          #untrusted host
          elif(ipv4.dstip == "106.44.82.103"):
            route(7)

          #departments
          elif(ipv4.dstip == "10.1.1.10"):
            route(1)
          elif(ipv4.dstip == "10.1.2.20"):
            route(1)
          elif(ipv4.dstip == "10.1.3.30"):
            route(2)
          elif(ipv4.dstip == "10.1.4.40"):
            route(2)
          elif(ipv4.dstip == "10.2.5.50"):
            route(3)
          elif(ipv4.dstip == "10.2.6.60"):
            route(3)
          elif(ipv4.dstip == "10.2.7.70"):
            route(4)
          elif(ipv4.dstip == "10.2.8.80"):
            route(4)

      elif icmp:
        if switch_id == 1:
          if ipv4.dstip == "10.1.1.10":
            route(8)
          elif ipv4.dstip == "10.1.2.20":
            route(9)
          else:
            route(1)
        
        elif switch_id == 2:
          if ipv4.dstip == "10.1.3.30":
            route(10)
            #print ("routed h30")
          elif ipv4.dstip == "10.1.4.40":
            route(11)
          else:
            route(1)
        
        elif switch_id == 3:
          if ipv4.dstip == "10.2.5.50":
            route(12)
            #print ("routed h50")
          elif ipv4.dstip == "10.2.6.60":
            route(13)
          else:
            route(1)

        elif switch_id == 4:
          if ipv4.dstip == "10.2.7.70":
            route(14)
          elif ipv4.dstip == "10.2.8.80":
            route(15)
          else:
            route(1)
        
        elif switch_id == 6:
          if ipv4.dstip == "10.3.9.90":
            route(16)
          else:
            route(1)
        
        elif switch_id == 5:
          #for department A
          if (ipv4.srcip == "108.24.31.112" or ipv4.srcip == "10.1.1.10" or ipv4.srcip == "10.1.2.20" or ipv4.srcip == "10.1.3.30" or ipv4.srcip == "10.1.4.40"):
            #print("department A")
            if(ipv4.dstip == "10.2.5.50" or ipv4.dstip == "10.2.6.60" or ipv4.dstip == "10.2.7.70" or ipv4.dstip == "10.2.8.80"):
              drop()
            else:
              if(ipv4.dstip == "108.24.31.112"):
                route(6)
              elif(ipv4.dstip == "10.1.1.10"):
                route(1)
              elif(ipv4.dstip == "10.1.2.20"):
                route(1)
              elif(ipv4.dstip == "10.1.3.30"):
                route(2)
              elif(ipv4.dstip == "10.1.4.40"):
                route(2)
              elif(ipv4.dstip == "10.3.9.90"):
                if (ipv4.srcip == "108.24.31.112"):
                  drop()
                else:
                  route(5)
              elif(ipv4.dstip == "106.44.82.103" and ipv4.srcip == "108.24.31.112" ):
                route(7)
          
          #for department B
          elif (ipv4.srcip == "10.2.5.50" or ipv4.srcip == "10.2.6.60" or ipv4.srcip == "10.2.7.70" or ipv4.srcip == "10.2.8.80"):
            if(ipv4.dstip == "10.1.1.10" or ipv4.dstip == "10.1.2.20" or ipv4.dstip == "10.1.3.30" or ipv4.dstip == "10.1.4.40"):
              drop()
            else:
              if(ipv4.dstip == "10.2.5.50"):
                route(3)
              elif(ipv4.dstip == "10.2.6.60"):
                route(3)
              elif(ipv4.dstip == "10.2.7.70"):
                route(4)
              elif(ipv4.dstip == "10.2.8.80"):
                route(4)
              elif(ipv4.dstip == "10.3.9.90"):
                route(5)
          
          #untrusted host
          elif(ipv4.srcip == "106.44.82.103"):
            if(ipv4.dstip == "108.24.31.112"):
              route(6)
            else:
              drop()
          
          # server
          elif (ipv4.srcip == "10.3.9.90"):
            if(ipv4.dstip == "10.1.1.10"):
              route(1)
            elif(ipv4.dstip == "10.1.2.20"):
              route(1)
            elif(ipv4.dstip == "10.1.3.30"):
              route(2)
            elif(ipv4.dstip == "10.1.4.40"):
              route(2)
            elif(ipv4.dstip == "10.2.5.50"):
              route(3)
            elif(ipv4.dstip == "10.2.6.60"):
              route(3)
            elif(ipv4.dstip == "10.2.7.70"):
              route(4)
            elif(ipv4.dstip == "10.2.8.80"):
              route(4)

    # all other traffic Flood
    #elif tcp:
    #  flood()
    else:
      print("other flood")
      flood()
    

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
