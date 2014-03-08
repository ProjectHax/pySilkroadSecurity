#!/usr/bin/env python
import os
import socket
import select
import errno
from time import sleep

from pySilkroadSecurity import SilkroadSecurity
from stream import *

# Replace with your IP address
bind_ip = ''
bind_port = 15779

gateway_host = 'gwgt1.joymax.com'
gateway_port = 15779

agent_connect = False
agent_host = ''
agent_port = 0

class Silkroad(object):

	s = None
	listen_s = None
	security = None

	def __init__(self):
		''''''

	def connect(self, host, port):
		self.close()
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((host, port))
		self.s.setblocking(False)
		self.security = SilkroadSecurity()

	def listen(self, host, port):
		self.close()

		if self.listen_s is not None:
			self.listen_s.close()

		self.listen_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.listen_s.bind((host, port))
		self.listen_s.setblocking(False)
		self.listen_s.listen(1)

	def accept(self):
		if self.listen_s is not None:
			self.s, address = self.listen_s.accept()

			self.s.setblocking(False)
			self.security = SilkroadSecurity()
			self.security.GenerateHandshake(True, True, True)

	def recv(self, size=8192):
		try:
			data = self.s.recv(size)
			if data is not None:
				self.security.Recv(list(data))
		except:
			self.close()

	def send(self, data):
		try:
			while data:
			    sent = self.s.send(data)
			    data = data[sent:]
		except:
			self.close()

	def close(self):
		if self.s is not None:
			try:
				self.s.shutdown(socket.SHUT_RDWR)
				self.s.close()

				self.s = None
				self.security = None
			except:
				''''''

def HandlePacket_Joymax(joymax, silkroad, packet):

	#print('Joymax\n%s' % packet)

	r = stream_reader(packet['data'])

	if packet['opcode'] == 0xA102:
		
		if r.read_uint8() == 1:

			global agent_connect, agent_host, agent_port

			agent_connect = True

			login_id = r.read_uint32()

			agent_host = r.read_ascii(r.read_uint16())
			agent_port = r.read_uint16()

			w = stream_writer()
			w.write_uint8(1)
			w.write_uint32(login_id)
			w.write_uint16(len(bind_ip))
			w.write_ascii(bind_ip)
			w.write_uint16(bind_port)
			silkroad.security.Send(0xA102, w.tolist(), True)

			return False

	return True

def HandlePacket_Silkroad(joymax, silkroad, packet):

	#print('Silkroad\n%s' % packet)

	if packet['opcode'] == 0x2001:
		return False

	return True

def main():

	joymax = Silkroad()
	silkroad = Silkroad()

	silkroad.listen(bind_ip, bind_port)

	try:
		while 1:

			sockets = []
			if silkroad.listen_s is not None:
				sockets.append(silkroad.listen_s)
			if silkroad.s is not None:
				sockets.append(silkroad.s)
			if joymax.s is not None:
				sockets.append(joymax.s)

			ready_to_read, ready_to_write, in_error = select.select(
				sockets,
				sockets,
				sockets,
				0.01
			)

			# Accept
			if silkroad.listen_s in ready_to_read:
				silkroad.accept()

				global agent_connect
				if agent_connect:
					agent_connect = False
					joymax.connect(agent_host, agent_port)
				else:
					joymax.connect(gateway_host, gateway_port)

			# Joymax
			if joymax.s in ready_to_read:

				joymax.recv()

				packets = joymax.security.GetPacketToRecv()
				if packets is not None:
					for p in packets:
						if HandlePacket_Joymax(joymax, silkroad, p):
							silkroad.security.Send(p['opcode'], p['data'], p['encrypted'], p['massive'])

			if joymax.s in ready_to_write:
				packets = joymax.security.GetPacketToSend()
				if packets is not None:
					for p in packets:
						joymax.send(bytes(p))

			# Silkroad
			if silkroad.s in ready_to_read:

				silkroad.recv()

				packets = silkroad.security.GetPacketToRecv()
				if packets is not None:
					for p in packets:
						if HandlePacket_Silkroad(joymax, silkroad, p):
							joymax.security.Send(p['opcode'], p['data'], p['encrypted'], p['massive'])

			if silkroad.s in ready_to_write:
				packets = silkroad.security.GetPacketToSend()
				if packets is not None:
					for p in packets:
						silkroad.send(bytes(p))

			# Errors
			if joymax.s in in_error:
				joymax.close()

			if silkroad.s in in_error:
				silkroad.close()

			sleep(0.01)
	except KeyboardInterrupt:
		''''''

	return 0

if __name__ == '__main__':
	os._exit(main())