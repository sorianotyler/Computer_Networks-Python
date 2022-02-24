# Tyler Soriano 1545385  
# CSE 150 
# Lab 3 
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
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

  def do_firewall (self, packet, packet_in):
    
    # The code in here will be executed for every packet.
    Msg = of.ofp_flow_mod()           #sets msg to table entry 
    
    #set the time timeouts
    Msg.idleTimeout = 30 #flow entry is removed from the flow table and the hardware after 30 sec bc no packets match it
    Msg.hardTimeout = 50 #flow entry is removed from the flow table and the hardware whether or not packets match it

    #handles the TCP case - if just TCP - drop, if TCP and IVP4 - check 
    if packet.find('tcp'):            # if it is a TCP we much check if it is IPV$
      if packet.find('ipv4'):                               
        Msg.data = packet_in                       # set data to packet in 
        Msg.match = of.ofp_match.from_packet(packet)       # compare if Packet_in data matches packet data
        Msg.priority = 1                                  #tcp is priority 1
        Msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) #sends the packet out all ports except the one the packet originally arrived on.
        self.connection.send(Msg) #send message to switch

  	#if arp - check
    elif packet.find('arp'):
      Msg.data = packet_in                #set data to packet in
      Msg.match = of.ofp_match.from_packet(packet)        # compare if Packet_in data matches packet dat
      Msg.priority = 2                          #arp is priority 2
      Msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))#sends the packet out all ports except the one the packet originally arrived on.
      self.connection.send(Msg) #send message to switch
  
    #any other packet can be dropped
    else:
      Msg.match = of.ofp_match.from_packet(packet)#matches
      #need to send message before getting dropped
      self.connection.send(Msg) 
    


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

