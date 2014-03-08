#!/usr/bin/env python
import struct
import array

class stream_reader(object):

	index = 0
	data = None
	size = 0

	def __init__(self, data, index=0):
		if type(data) == list:
			self.data = array.array('B', data)
		elif type(data) != array.array:
			raise Exception('incorrect data type was used to initialize the class')
		else:
			self.data = data
		self.size = self.data.__len__()
		self.seek_set(index)

	def reset(self, data, index=0):
		if type(data) == list:
			self.data = array.array('B', data)
		elif type(data) != array.array:
			raise Exception('incorrect data type was used to reset the class')
		else:
			self.data = data
		self.size = self.data.__len__()
		self.seek_set(index)

	def bytes_left(self):
		return self.size - self.index

	def seek_forward(self, count):
		if self.index + count > self.size:
			raise Exception('index would be past end of stream')
		self.index += count

	def seek_backward(self, count):
		if self.index - count < 0:
			raise Exception('index would be < 0 if seeked further back')
		self.index -= count

	def seek_set(self, index):
		if index > self.size or index < 0:
			raise Exception('invalid index')
		self.index = index

	def read_int8(self):
		if self.index + 1 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('b', self.data, self.index)[0]
		self.index += 1
		return unpacked

	def read_uint8(self):
		if self.index + 1 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('B', self.data, self.index)[0]
		self.index += 1
		return unpacked

	def read_int16(self):
		if self.index + 2 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('h', self.data, self.index)[0]
		self.index += 2
		return unpacked

	def read_uint16(self):
		if self.index + 2 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('H', self.data, self.index)[0]
		self.index += 2
		return unpacked

	def read_int32(self):
		if self.index + 4 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('i', self.data, self.index)[0]
		self.index += 4
		return unpacked

	def read_uint32(self):
		if self.index + 4 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('I', self.data, self.index)[0]
		self.index += 4
		return unpacked

	def read_int64(self):
		if self.index + 8 > self.size:
			raise Exception('read_int64 - past end of stream')
		unpacked = struct.unpack_from('q', self.data, self.index)[0]
		self.index += 8
		return unpacked

	def read_uint64(self):
		if self.index + 8 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('Q', self.data, self.index)[0]
		self.index += 8
		return unpacked

	def read_float(self):
		if self.index + 4 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('f', self.data, self.index)[0]
		self.index += 4
		return unpacked

	def read_double(self):
		if self.index + 8 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('d', self.data, self.index)[0]
		self.index += 8
		return unpacked

	def read_char(self):
		if self.index + 1 > self.size:
			raise Exception('past end of stream')
		unpacked = struct.unpack_from('c', self.data, self.index)[0]
		self.index += 1
		return unpacked

	def read_ascii(self, length):
		if self.index + length > self.size:
			raise Exception('past end of stream')
		string = struct.unpack_from(str(length) + 's', self.data, self.index)[0]
		self.index += length
		return string.decode('ascii', 'replace')

	'''
	def read_utf8(self, length):
		if self.index + length > self.size:
			raise Exception('past end of stream')
		string = struct.unpack_from(str(length) + 's', self.data, self.index)[0]
		self.index += length
		return string.decode('utf-8')
	'''

	def read_utf16(self, length):
		length *= 2
		if self.index + length > self.size:
			raise Exception('past end of stream')
		string = struct.unpack_from(str(length) + 's', self.data, self.index)[0]
		self.index += length
		return string.decode('utf-16le')

	def read_utf32(self, length):
		length *= 4
		if self.index + length > self.size:
			raise Exception('past end of stream')
		string = struct.unpack_from(str(length) + 's', self.data, self.index)[0]
		self.index += length
		return string.decode('utf-32le')

class stream_writer(object):

	data = array.array('B')
	index = 0
	size = 0

	def __init__(self, data=array.array('B')):
		if type(data) == list:
			self.data = array.array('B', data)
		elif type(data) != array.array:
			raise Exception('stream_writer - incorrect data type was used to initialize the class')
		else:
			self.data = data

	def reset(self, data=array.array('B')):
		if type(data) == list:
			self.data = array.array('B', data)
		elif type(data) != array.array:
			raise Exception('reset - incorrect data type was used to initialize the class')
		else:
			self.data = data

		self.size = self.data.__len__()
		self.seek_end()

	def tostring(self):
		return self.data.tostring()

	def tolist(self):
		return self.data.tolist()

	def tofile(self, f):
		return self.data.tofile(f)

	def toarray(self):
		return self.data

	def seek_forward(self, count):
		if self.index + count > self.size:
			raise Exception('seek_forward - index would be past end of stream')
		self.index += count

	def seek_backward(self, count):
		if self.index - count < 0:
			raise Exception('seek_backward - index would be < 0 if seeked further back')
		self.index -= count

	def seek_set(self, index):
		if index > self.size or index < 0:
			raise Exception('seek_set - invalid index')
		self.index = index

	def seek_end(self):
		self.index = self.size

	def write_int8(self, val):
		self.__append(struct.pack('b', val))

	def write_uint8(self, val):
		self.__append(struct.pack('B', val))

	def write_int16(self, val):
		self.__append(struct.pack('h', val))

	def write_uint16(self, val):
		self.__append(struct.pack('H', val))

	def write_int32(self, val):
		self.__append(struct.pack('i', val))

	def write_uint32(self, val):
		self.__append(struct.pack('I', val))

	def write_int64(self, val):
		self.__append(struct.pack('q', val))

	def write_uint64(self, val):
		self.__append(struct.pack('Q', val))

	def write_float(self, val):
		self.__append(struct.pack('f', val))

	def write_double(self, val):
		self.__append(struct.pack('d', val))

	def write_char(self, val):
		self.__append(struct.pack('c', val))

	def write_ascii(self, val):
		self.__append(bytes(val, 'ascii', 'replace'))

	'''
	def write_utf8(self, val):
		self.__append(bytes(val, 'utf-8'))
	'''

	def write_utf16(self, val):
		self.__append(val.encode('utf-16le'))

	def write_utf32(self, val):
		self.__append(val.encode('utf-32le'))

	def write(self, val):
		self.__append(val)

	def __append(self, packed):
		for x in packed:
			self.data.insert(self.index, x)
			self.index += 1
			self.size += 1

if __name__ == '__main__':

	w = stream_writer()
	w.write_uint8(4)
	w.write_ascii('test')
	w.write_uint32(1337)
	w.write_int64(-1337313371337)
	w.write_double(1337.31337)
	w.write([0x75, 0x00, 0x74, 0x00, 0x66, 0x00, 0x31, 0x00, 0x36, 0x00, 0x20, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6b, 0x00, 0x73, 0x00])

	hex_string = w.tostring()
	hex_list = w.tolist()
	hex_array = w.toarray()

	print('String: %s' % hex_string)
	print('List: %s' % hex_list)
	print('Array: %s\n' % hex_array)

	''''''''''''''''''''''''''''''''''''''''''''''''''''''

	r = stream_reader(hex_array)
	length = r.read_uint8()
	string = r.read_ascii(length)
	integer = r.read_uint32()
	integer_64 = r.read_int64()
	double = r.read_double()
	utf16 = r.read_utf16(11)

	print('Extracted length: \'%d\'' % length)
	print('Extracted string: \'%s\'' % string)
	print('Extracted number: \'%s\'' % integer)
	print('Extracted signed 64-bit integer: \'%s\'' % integer_64)
	print('Extracted double: \'%s\'' % double)
	print('UTF-16: \'%s\'' % utf16)
	print('Bytes left: \'%s\'' % r.bytes_left())