#!/usr/bin/python

import math, socket, ssl, select, time, threading, random, string, os
from collections import deque

EOC = "\r\n"

config_ownhost = "ircd.local"
config_password = ""
config_netname = "Cryto IRC"
config_version = "circd 0.1"

def remove_from_list(ls, val):
	return [value for value in ls if value is not val]

def split_irc(message):
	if ":" in message:
		first, second = message.split(":", 2)
		return first.rstrip().split(" ") + [second]
	else:
		return message.split(" ")

class ircd:
	channels = {}
	users = {}

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
							
							new_client = client(connstream, remote_ip)
							
							self.select_inputs.append(connstream)
							self.select_outputs.append(connstream)
							self.client_map[connstream.fileno()] = new_client
							self.client_list.append(new_client)
						else:
							data = sock.recv(1024)
							cur_client = self.client_map[sock.fileno()]
							
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
	ip = ""
	
	def __init__(self, connstream, ip):
		self.ip = ip
		self.stream = connstream
		self.user = user(self)
	
	def send_chunk(self, chunk):
		self.stream.send(chunk + EOC)
	
	def send_global_notice(self, notice):
		self.send_chunk(":%s NOTICE %s" % (config_ownhost, notice))
		
	def send_numeric(self, numeric, notice):
		self.send_chunk(":%s NOTICE %s %s" % (config_ownhost, numeric, notice))
	
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
		pass

class channel:
	presences = {}
	name = ""
	registered = False
	
class user:
	client = None
	registered = 0
	registered_nick = False
	registered_user = False
	nickname = ""
	ident = ""
	realname = ""
	masked_host = ""
	real_host = ""
	ip = ""
	
	def __init__(self, client):
		self.client = client		
		self.client.send_global_notice("AUTH :*** Looking up your hostname...")
		hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(self.client.ip)
		self.real_host = hostname
		self.masked_host = hostname
		self.client.send_global_notice("AUTH :*** Found your hostname")
		if config_password == "":
			self.registered = 1
			
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
					self.client.send_numeric("461", "%s USER :Not enough parameters." % self.nickname)
			elif data[0] == "NICK":
				if len(data) >= 2:
					self.nickname = data[1]
					self.registered_nick = True
					self.verify_registration()
				else:
					self.client.send_numeric("461", "%s NICK :Not enough parameters." % self.nickname)
		elif self.registered == 2 and data[0] == "PONG":
			if data[1] == self.challenge:
				self.finish_registration()
		elif self.registered < 2:
			self.client.send_numeric("451", "%s %s :You have not registered." % (self.nickname, data[0]))
		elif self.registered < 3:
			self.client.send_numeric("451", "%s %s :You have not completed the challenge PING." % (self.nickname, data[0]))
		else:
			print "Received %s command." % data[0]
	
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
		self.client.send_numeric("001", ":Welcome to %s, %s!%s@%s" % (config_netname, self.nickname, self.ident, self.real_host))
		self.client.send_numeric("002", ":Your host is %s, running %s." % (config_ownhost, config_version))
		self.client.send_numeric("003", ":This server has been running since unknown.")
		self.client.send_numeric("004", ":%s %s %s %s" % (config_ownhost, config_version, "", ""))
	
class presence:
	user = None
	status = "none"
	joined = 0

server = ircd()

l = listener(server)
l.start("0.0.0.0", 6667, "sample.cert", "sample.key")
