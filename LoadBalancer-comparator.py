"""
Python script to balance the incoming load
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.revent import EventContinue,EventHalt
from pox.lib.util import dpidToStr
from pox.lib.packet.arp import arp
import sys, re

log = core.getLogger()

############## Constants #############

# LOAD_BALANCER_ALGO = 0 for Round Robin
# LOAD_BALANCER_ALGO = 1 for Priority
# LOAD_BALANCER_ALGO = 2 for Least Connections

LOAD_BALANCER_ALGO = 0

IDLE_TIMEOUT = 3 # in seconds
HARD_TIMEOUT = 5 # in seconds

WEB_SERVER_IP = IPAddr('10.0.0.5')
WEB_SERVER_MAC = EthAddr('00:00:00:00:00:05')

server = {}
server[0] = {'ip':IPAddr("10.0.0.2"), 'mac':EthAddr("00:00:00:00:00:02"), 'outport': 2}
server[1] = {'ip':IPAddr("10.0.0.3"), 'mac':EthAddr("00:00:00:00:00:03"), 'outport': 3}
server[2] = {'ip':IPAddr("10.0.0.4"), 'mac':EthAddr("00:00:00:00:00:04"), 'outport': 4}
total_servers = len(server)

source_ip = IPAddr("10.0.0.1")
source_map = EthAddr("00:00:00:00:00:01")

### Assigning the priority of the servers manually based on the bandwidth and other parameters
priority_server0 = 1
priority_server1 = 2
priority_server2 = 3

##############   #############

class my_controller(object):

	"""docstring for my_controller"""
	def __init__ (self, connection):
		self.connection = connection            # Get a lock on connection to switch
		connection.addListeners(self)           # Bind the packet listner
		self.macToPort = {}                     # Initialize the dictionary to keep track of source/destination port address
		self.server_index = 0
		index = 0
		pass

	def handleARPmessages (self, packet, event):
		in_port = event.port
		# Get the ARP request from packet
		arp_req = packet.next

		# Create ARP reply
		arp_rep = arp()
		arp_rep.opcode = arp.REPLY
		arp_rep.hwsrc = WEB_SERVER_MAC
		arp_rep.hwdst = arp_req.hwsrc
		arp_rep.protosrc = WEB_SERVER_IP
		arp_rep.protodst = arp_req.protosrc

		# Create the Ethernet packet
		eth = ethernet()
		eth.type = ethernet.ARP_TYPE
		eth.dst = packet.src
		eth.src = WEB_SERVER_MAC
		eth.set_payload(arp_rep)

		# Send the ARP reply to client
		msg = of.ofp_packet_out()
		msg.data = eth.pack()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.in_port = in_port
		self.connection.send(msg)
		pass

	def prioritize_server_for_priority():
		if priority_server0 == 1:
			if ######Bandwidth used is not more than threshold
				return 1
		elif priority_server1 == 1:
			if ######Bandwidth used is not more than threshold
				return 2
		elif priority_server2 == 1:
			if ######Bandwidth used is not more than threshold
				return 3

		elif priority_server0 == 2:
			if ######Bandwidth used is not more than threshold
				return 1
		elif priority_server1 == 2:
			if ######Bandwidth used is not more than threshold
				return 2
		elif priority_server2 == 2:
			if ######Bandwidth used is not more than threshold
				return 3

		elif priority_server0 == 3:
			if ######Bandwidth used is not more than threshold
				return 1
		elif priority_server1 == 3:
			if ######Bandwidth used is not more than threshold
				return 2
		elif priority_server2 == 3:
			if ######Bandwidth used is not more than threshold
				return 3
		pass

	def prioritize_server_for_least_connections():
		if ######Bandwidth used is not more than threshold for server1
				return 1
		elif ######Bandwidth used is not more than threshold for server2
				return 2
		elif ######Bandwidth used is not more than threshold for server3
				return 3
		pass

		
	def generate_server_index():
		


		if LOAD_BALANCER_ALGO == 0:	### LOAD_BALANCER_ALGO = 0 for Round Robin
			self.server_index =  (self.server_index +1 ) % total_servers_index
			log.debug ("The Server Currently Serving is  %s" % self.server)

		if LOAD_BALANCER_ALGO == 1: ### LOAD_BALANCER_ALGO = 1 for Priority
			self.server_index = prioritize_server_for_priority()
			log.debug ("The Server Currently Serving is  %s" % self.server_index)

		if LOAD_BALANCER_ALGO == 2: ### LOAD_BALANCER_ALGO = 2 for Least Connections
			self.server_index = prioritize_server_for_least_connections()
			log.debug ("The Server Currently Serving is  %s" % self.server_index)

		return self.server_index
		pass

	def act_like_load_bal(self, packet, packet_in, event):
		src_mac = packet.src
		dst_mac = packet.dst
		src_port = packet_in.in_port
		# dst_port = packet.port

		index = generate_server_index()

		selected_server_ip = server[index]['ip']
		selected_server_mac = server[index]['mac']
		selected_server_outport = server[index]['outport']

		msg = of.ofp_flow_mod()	
		msg.idle_timeout = IDLE_TIMEOUT
		msg.hard_timeout = HARD_TIMEOUT
		msg.buffer_id = None

		# Set packet matching
		# Match (in_port, src MAC, dst MAC, src IP, dst IP)
		msg.match.in_port = selected_server_outport
		msg.match.dl_src = selected_server_mac
		msg.match.dl_dst = packet.src
		msg.match.dl_type = ethernet.IP_TYPE
		msg.match.nw_src = selected_server_ip
		msg.match.nw_dst = packet.next.srcip

		# Append actions
		# Set the src IP and MAC to load balancer's
		# Forward the packet to client's port
		msg.actions.append(of.ofp_action_nw_addr.set_src(WEB_SERVER_IP))
		msg.actions.append(of.ofp_action_dl_addr.set_src(WEB_SERVER_MAC))
		msg.actions.append(of.ofp_action_output(port = event.port))

		self.connection.send(msg)

		"Second install the forward rule from client to server"
		msg = of.ofp_flow_mod()
		msg.idle_timeout = IDLE_TIMEOUT
		msg.hard_timeout = HARD_TIMEOUT
		msg.buffer_id = None
		msg.data = event.ofp # Forward the incoming packet

		# Set packet matching
		# Match (in_port, MAC src, MAC dst, IP src, IP dst)
		msg.match.in_port = event.port
		msg.match.dl_src = packet.src
		msg.match.dl_dst = WEB_SERVER_MAC
		msg.match.dl_type = ethernet.IP_TYPE
		msg.match.nw_src = packet.next.srcip
		msg.match.nw_dst = WEB_SERVER_IP
		
		# Append actions
		# Set the dst IP and MAC to load balancer's
		# Forward the packet to server's port
		msg.actions.append(of.ofp_action_nw_addr.set_dst(selected_server_ip))
		msg.actions.append(of.ofp_action_dl_addr.set_dst(selected_server_mac))
		msg.actions.append(of.ofp_action_output(port = selected_server_outport))

		self.connection.send(msg)

		log.info("Installing %s <-> %s" % (packet.next.srcip, selected_server_ip))


	def act_like_switch(self, packet, packet_in):
		src_mac = packet.src
		dst_mac = packet.dst
		src_port = packet_in.in_port
		# dst_port = packet.port

		if dst_mac in self.macToPort:
			dst_port = self.macToPort[dst_mac]
			log.debug("act_like_switch(): Flow for %s.%i -> %s.%i" % (packet.src, src_port, packet.dst, dst_port))
			self.server_index =  (self.server_index +1 ) % total_servers
			
			msg = of.ofp_flow_mod()
			#
			## Set fields to match received packet
			msg.match = of.ofp_match.from_packet(packet, src_port)
			msg.idle_timeout = IDLE_TIMEOUT
			msg.hard_timeout = HARD_TIMEOUT
			msg.actions.append(of.ofp_action_output(port = dst_port))
			msg.data = packet_in 
			self.connection.send(msg)
		else:
			log.debug("ELSE: act_like_switch(): Flow for %s.%i -> %s.??" % (packet.src, src_port, packet.dst))
			self.resend_packet(packet_in, of.OFPP_ALL)
		pass

	def resend_packet(self, packet_in, out_port):
		# log.debug ("resend_packet(): Forwarding the pocket to all ports")
		msg = of.ofp_packet_out()
		msg.data = packet_in

		# Add an action to send to the specified port
		action = of.ofp_action_output(port = out_port)
		msg.actions.append(action)

		# Send message to switch
		self.connection.send(msg)
		pass

	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		packet = event.parsed # This is the parsed packet data.
		packet_in = event.ofp
		self.macToPort[packet.src] = event.port

		pingmsg = of.ofp_flow_mod()
		pingmsg.match = of.ofp_match.from_packet(packet, packet_in.in_port)

		ip_addr_src = pingmsg.match.nw_dst

		if ip_addr_src == WEB_SERVER_IP:
			log.debug ("####: Load balancing for %s" % ip_addr_src)
			if packet.type == packet.ARP_TYPE:
				self.handleARPmessages(packet, event)
			self.act_like_load_bal (packet, packet_in, event)
			return 0

		if not packet.parsed:
			log.warning("### Ignoring incomplete packet")
			return -1
		if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
			# log.debug("_handle_PacketIn(): Received an IPV6 packet from %s" % packet.next.srcip)
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port
			self.connection.send(msg)

		elif packet.type == packet.ARP_TYPE:
			# Handle ARP request for load balancer
			# Only accept ARP request for load balancer
			# log.debug("_handle_PacketIn(): Received an ARP request")
			# self.handleARPmessages(packet, event)
			self.resend_packet(packet_in, of.OFPP_ALL)
			pass

		elif packet.type == packet.IP_TYPE:
			# Handle client's request
			# Only accept ARP request for load balancer
			# log.debug("_handle_PacketIn(): Received an IPv4 packet from %s" % packet.next.srcip)
			self.act_like_switch(packet, packet_in)
			# self.act_like_load_bal(packet, packet_in)
		pass

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
	log.debug("### Controlling %s" % (event.connection,))
	my_controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)