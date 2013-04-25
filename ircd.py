#!/usr/bin/python

import math, socket, ssl, select, time, threading, random, string, os
from collections import deque

EOC = "\r\n"

config_ownhost = "ircd.local"
config_password = ""
config_netname = "Cryto IRC"
config_version = "circd 0.1"
config_motd = "sample.motd"

def remove_from_list(ls, val):
	return [value for value in ls if value is not val]

def split_irc(message):
	if ":" in message:
		first, second = message.split(":", 2)
		return first.rstrip().split(" ") + [second]
	else:
		return message.split(" ")

class autodict(dict):
	# http://stackoverflow.com/a/652284
	def __getitem__(self, item):
		try:
			return dict.__getitem__(self, item)
		except KeyError:
			value = self[item] = type(self)()
			return value
			
class ircd:
	channels = {}
	users = {}
	motd = ""
	
	def __init__(self):
		if config_motd != "":
			try:
				self.motd = open(config_motd, "r").read()
			except IOError:
				print "WARNING: Could not read MOTD file."

class listener:
	ssl = False
	server = None
	client_list = []
	client_map = {}
	select_inputs = []
	select_outputs = []
	
	def __init__(self, server):
		self.server = server
		
	def start(self, interface, port, cert_path, key_path):
		bindsocket = socket.socket()
		bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		bindsocket.bind((interface, port))
		bindsocket.listen(5)

		self.select_inputs = [ bindsocket ]

		while self.select_inputs:
			readable, writable, error = select.select(self.select_inputs, self.select_outputs, self.select_inputs)
			
			if len(readable) > 0:
				for sock in readable:
					try:
						if sock is bindsocket:
							newsocket, fromaddr = bindsocket.accept()
							remote_ip, remote_port = fromaddr
							
							if self.ssl == True:
								connstream = ssl.wrap_socket(newsocket, server_side=True, certfile=cert_path, keyfile=key_path, ssl_version=ssl.PROTOCOL_TLSv1)
							else:
								connstream = newsocket
							
							new_client = client(connstream, remote_ip, server, self)
							
							self.select_inputs.append(connstream)
							self.select_outputs.append(connstream)
							self.client_map[connstream.fileno()] = new_client
							self.client_list.append(new_client)
						else:
							cur_client = self.client_map[sock.fileno()]
							
							try:
								data = sock.recv(1024)
							except socket.error, (value, message):
								cur_client.abort(message)
							else:
								if data:
									cur_client.process_data(data)
								else:
									cur_client.end()
									self.select_inputs = remove_from_list(self.select_inputs, sock)
									print "NOTICE: Client disconnected"
					except ssl.SSLError, err:
						if err.args[0] == ssl.SSL_ERROR_WANT_READ:
							select.select([sock], [], [])
						elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
							select.select([], [sock], [])
						else:
							raise
			else:
				time.sleep(0.010)

class client:
	buff = ""
	stream = None
	user = None
	listener = None
	ip = ""
	
	def __init__(self, connstream, ip, server, listener):
		self.ip = ip
		self.stream = connstream
		self.user = user(self, server)
		self.listener = listener
	
	def abort(self, reason):
		# TODO: Log quit reason
		try:
			self.stream.shutdown(2)
			self.close()
		except socket.error:
			pass
			
		self.end()
		self.listener.select_inputs = remove_from_list(self.listener.select_inputs, self.stream)
		print "NOTICE: Client disconnected, possibly due to socket error: %s" % reason

	def send_chunk(self, chunk):
		#print chunk
		try:
			self.stream.send(chunk + EOC)
		except socket.error, (value, message):
			self.abort(message)
	
	def send_global_notice(self, notice):
		self.send_chunk(":%s NOTICE %s" % (config_ownhost, notice))
		
	def send_numeric(self, numeric, notice):
		self.send_chunk(":%s %s %s %s" % (config_ownhost, numeric, self.user.nickname, notice))
		
	def send_event(self, origin, event, message):
		self.send_chunk(":%s %s %s" % (origin, event, message))
	
	def process_data(self, data):
		self.buff += data
		stack = self.buff.split("\n")
		self.buff = stack.pop()
		
		for chunk in stack:
			print chunk
			self.process_chunk(chunk.rstrip())
	
	def process_chunk(self, chunkdata):
		data = split_irc(chunkdata)
		if data[0].upper() == "PING":
			self.send_chunk("PONG %s" % data[1])
		else:
			self.user.process_data(data)
	
	def end(self):
		if self.user is not None:
			self.user.end()

class channel:
	presences = {}
	name = ""
	registered = False
	
	def __init__(self, channelname):
		self.name = channelname
	
class user:
	client = None
	server = None
	registered = 0
	registered_nick = False
	registered_user = False
	presences = {}
	nickname = "*"
	ident = ""
	realname = ""
	masked_host = ""
	real_host = ""
	ip = ""
	
	def __init__(self, client, server):
		self.server = server
		self.client = client		
		self.client.send_global_notice("AUTH :*** Looking up your hostname...")
		
		try:
			hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(self.client.ip)
			self.client.send_global_notice("AUTH :*** Found your hostname")
		except socket.herror:
			hostname = self.client.ip
			self.client.send_global_notice("AUTH :*** Could not find your hostname, using IP address instead")
			
		self.real_host = hostname
		self.masked_host = hostname
		
		if config_password == "":
			self.registered = 1
	
	def __str__(self):
		return "%s!%s@%s" % (self.nickname, self.ident, self.masked_host)
			
	def process_data(self, data):
		data = deque(data)
		
		if data[0].startswith(":"):
			origin = data.popleft()
		else:
			origin = ""
		
		data[0] = data[0].upper()
		
		if data[0] in ["USER", "NICK"] and self.registered == 1:
			if data[0] == "USER":
				if len(data) >= 5:
					self.ident = data[1]
					self.realname = data[4]
					self.registered_user = True
					self.verify_registration()
				else:
					self.client.send_numeric("461", "USER :Not enough parameters.")
			elif data[0] == "NICK":
				if len(data) >= 2:
					if data[1] not in self.server.users:
						self.nickname = data[1]
						self.registered_nick = True
						self.verify_registration()
					else:
						self.client.send_numeric("433", "%s :Nickname is already in use." % data[1])
				else:
					self.client.send_numeric("461", "NICK :Not enough parameters.")
		elif self.registered == 2 and data[0] == "PONG":
			if data[1] == self.challenge:
				self.finish_registration()
		elif self.registered < 2:
			self.client.send_numeric("451", "%s :You have not registered." % data[0])
		elif self.registered < 3:
			self.client.send_numeric("451", "%s :You have not completed the challenge PING." % data[0])
		else:
			if data[0] == "LUSERS":
				self.send_lusers()
			elif data[0] == "JOIN":
				self.join_channel(data[1])
			else:
				self.client.send_numeric("421", "%s :Unknown command." % data[0])
	
	def verify_registration(self):
		if self.registered_nick == True and self.registered_user == True:
			self.registered = 2
			print "Client %s registered from IP %s, sending challenge string." % (self.nickname, self.client.ip)
			self.send_challenge()
			
	def send_challenge(self):
		self.challenge = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in xrange(8))
		self.client.send_chunk("PING :%s" % self.challenge)
		
	def finish_registration(self):
		self.registered = 3
		self.server.users[self.nickname] = self
		self.client.send_numeric("001", ":Welcome to %s, %s!%s@%s" % (config_netname, self.nickname, self.ident, self.real_host))
		self.client.send_numeric("002", ":Your host is %s, running %s." % (config_ownhost, config_version))
		self.client.send_numeric("003", ":This server has been running since unknown.")
		self.client.send_numeric("004", ":%s %s %s %s" % (config_ownhost, config_version, "", ""))
		self.send_lusers()
		self.send_motd()
	
	def send_lusers(self):
		self.client.send_numeric("251", ":There are %d users and 0 invisible on 1 server." % len(self.server.users))
		self.client.send_numeric("252", "%d :operator(s) online" % 0)
		self.client.send_numeric("254", "%d :channel(s) formed" % 0)
		self.client.send_numeric("255", ":I have %d clients and 1 server." % len(self.server.users))  # TODO: Sum all clients of all listenersm rather than taking the usercount.
	
	def send_motd(self):
		if server.motd == "":
			self.client.send_numeric("422", ":No MOTD was set.")
		else:
			self.client.send_numeric("375", ":- %s Message of the day -" % config_ownhost)
			
			for line in server.motd.rstrip().split("\n"):
				self.client.send_numeric("372", ":- %s" % line.rstrip())
				
			self.client.send_numeric("375", ":End of MOTD for %s." % config_ownhost)
	
	def join_channel(self, channelname):
		if channelname not in self.server.channels:
			self.server.channels[channelname] = channel(channelname)
		
		targetchannel = self.server.channels[channelname]
		
		if self.nickname not in targetchannel.presences:
			newpresence = presence(targetchannel, self)
			self.server.channels[channelname].presences[self.nickname] = newpresence
			self.presences[channelname] = newpresence
			self.client.send_event(self, "JOIN", ":%s" % channelname)
			self.client.send_numeric("353", "= %s :%s" % (channelname, "@hai blah"))
			self.client.send_numeric("366", "%s :End of userlist." % channelname)
			print self.server.channels[channelname].presences
			print self.presences[channelname]
	
	def end(self):
		del self.server.users[self.nickname]
	
class presence:
	user = None
	channel = None
	status = ""
	joined = 0
	
	def __init__(self, targetchannel, targetuser):
		self.user = targetuser
		self.channel = targetchannel
		self.status = ""

server = ircd()

l = listener(server)
l.start("0.0.0.0", 6667, "sample.cert", "sample.key")
