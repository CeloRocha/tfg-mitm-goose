import struct
import binascii
from scapy.all import *
from helper import *

class ASNType(object):
    tag = ''
    def __init__(self, data='', length=0):
        pass

    def unpack(self, data):
        raise NotImplemented()

    def pack(self, data):
        raise NotImplemented()

    def spoof(self):
        return self.data

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return str(self.data)

class Integer(ASNType):
    def __init__(self, data='', length=0):
        self.data = int.from_bytes(data, "big")
        # self.data = unpack_varint(data, length)

    def pack(self):
        if isinstance(self.data, int):
            if self.data <= 255:
                return struct.pack('!B', self.data)
            elif self.data <= 65535:
                return struct.pack('!h', self.data)
            else:
                return struct.pack('!i', self.data)
        if isinstance(self.data, long):
            return struct.pack('!l', self.data)

    def to(self, setpoint):
        self.data = setpoint

    def add(self, num):
        self.data += num

class VisibleString(ASNType):
    def __init__(self, data='', length=0):
        self.data = data

    def __str__(self):
        return self.data.decode()

    def __repr__(self):
        # return self.data
        return self.data.decode()

    def pack(self):
        return self.data

class Boolean(ASNType):
    ID = 3
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!b', data)[0]

    def __repr__(self):
        if self.data:
            return "True"
        else:
            return "False"

    def pack(self):
        return struct.pack('!b', self.data)

    def spoof(self, allData = False):
        if allData:
            self.data = not self.data

class UTCTime(ASNType):
    def __init__(self, data='', length=0):
        self.data = data

    def pack(self):
        return self.data

    def to(self, setpoint):
        res = bytearray()
        # First 4 bytes, represents seconds, 3 bytes represents the miliseconds fraction of a second by a negative power of N, which N is represented by the byte.
        # More info on iec61850-8-1ed2.0b annex F3.1
        res.extend(bitstring_to_bytes(float_to_binary(setpoint)))
        # Flags UTC - leap seconds known, no errors, non specified precision
        # More info on iec61850-8-1ed2.0b, section 8.1.3.7
        res.extend((159).to_bytes(1))
        self.data = res


class UnsignedInteger(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack()

class Float(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!f', data)[0]

    def pack(self):
        return struct.data('!f', data) 

class Real(Float):
    pass

class OctetString(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

class BitString(ASNType):
    ID = 4
    def __init__(self, data='', length=0):
        c = {'0': '0000', '1': '0001', '2': '0010', 
             '3':'0011', '4':'0100', '5':'0101', 
             '6':'0110', '7':'0111', '8':'1000', 
             '9':'1001', 'a':'1010', 'b':'1011', 
             'c':'1100', 'd':'1101', 'e':'1110', 
             'f':'1111'}
        self.padding = struct.unpack('!h', '\x00'+data[:1])[0]
        h = binascii.b2a_hex(data[1:])
        self.data = ''
        for i in h:
            self.data += c[i]

    def pack(self):
        packed_padding = struct.pack('!B', self.padding)
        packed_data = struct.pack('!h', int(self.data, 2))
        return packed_padding + packed_data

class ObjectID(ASNType):
    pass

class BCD(ASNType):
    pass

class BooleanArray(ASNType):
    pass

class UTF8String(ASNType):
    pass
    
class Data(object):
    tag = ''
    tagmap = {131:('boolean', Boolean), 
              132:('bitstring', BitString),
              133:('integer', Integer), 
              135:('float', Float), 
              136:('real', Real),
              137:('octetstring', OctetString)}

    def __init__(self, data=None, length=0):
        self.tagmap[161] = ('array', Data)
        self.tagmap[162] = ('structure', Data)
        self.data = decoder(data, self.tagmap, decode_as_list=True)

    def __getitem__(self, index):
        return self.data[index]

    def __repr__(self):
        return repr(self.data)

    def pack(self):
        """ This is a spoof, and should probably be integrated in to
            the BER encoder at some point.
        """
        packed_data = bytearray()
            # packed_data = ''
        for content in self.data:
            print("CONT", content)
            tag = struct.pack('!B', content.tag)
            package = content.pack()
            if len(package) < 128:
                length = struct.pack('!B', len(package))
            else:  # spoof.. this will only support lengths up to 254.
                length = struct.pack('!BB', 129, len(package))
            # packed_data += tag + length + package
            packed_data.extend(tag)
            packed_data.extend(length)
            packed_data.extend(package)

        return packed_data

    def spoof(self):
        for content in self.data:
            content.spoof(True)
        return self.data