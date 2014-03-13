#!/usr/bin/env python3
import os
import socket
import errno
from time import sleep

from pySilkroadSecurity import SilkroadSecurity
from stream import *

def HandlePacket(security, packet):

	r = stream_reader(packet['data'])

	if packet['opcode'] == 0x2001:

		server = r.read_ascii(r.read_uint16())

		if server == 'GatewayServer':

			w = stream_writer()
			w.write_uint8(18)
			w.write_uint16(9)
			w.write_ascii('SR_Client')
			w.write_uint32(432)
			security.Send(0x6100, w.tolist(), True)

	elif packet['opcode'] == 0xA100:

		security.Send(0x6101, [], True)

	elif packet['opcode'] == 0xA101:

		entry = r.read_uint8()
		while entry == 1:
			r.read_uint8()
			print(r.read_ascii(r.read_uint16()))
			entry = r.read_uint8()

		print('')

		entry = r.read_uint8()
		while entry == 1:
			server_id = r.read_uint16()

			name = r.read_ascii(r.read_uint16())
			capacity = r.read_float()
			state = r.read_uint8()

			print('[%s] %f' % (name, capacity * 100))

			entry = r.read_uint8()

def main():
	security = SilkroadSecurity()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('gwgt1.joymax.com', 15779))
	s.setblocking(False)

	try:
		while 1:
			try:
				data = s.recv(8192)

				if data is None:
					break

				# Packet received
				security.Recv(list(data))

				# See if there are packets that can be processed
				packet = security.GetPacketToRecv()
				if packet is not None:
					# Iterate each returned packet
					for p in packet:
						# Process the packet
						HandlePacket(security, p)

				# See if there are packets to be sent
				packet = security.GetPacketToSend()

				# Send each packet in the list
				if packet is not None:
					for p in packet:
						data = bytes(p)
						while data:
							sent = s.send(data)
							data = data[sent:]
			except socket.error as e:
				if e.errno == errno.EWOULDBLOCK:
					sleep(0.01)
				else:
					raise e
	except KeyboardInterrupt:
		''''''

	# Cleanup
	s.shutdown(socket.SHUT_RDWR)
	s.close()

	return 0

if __name__ == '__main__':
	os._exit(main())