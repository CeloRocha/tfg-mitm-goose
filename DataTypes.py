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

    def spoof(self, data = False):
        return self.data

    def __str__(self):
        return self.data

    def __repr__(self):
        return self.data
    
    def getData(self):
        return self.data

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
                return self.data.to_bytes(5)
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
        self.data = struct.unpack('f', data[1:])[0]

    def pack(self):
        
        res = bytearray()
        res.extend((8).to_bytes(1))
        res.extend(struct.pack('f', self.data))
        return res
class Real(Float):
    pass

class OctetString(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

class BitString(ASNType):
    ID = 4
    def __init__(self, data='', length=0):
        k = bytearray()
        k.extend(data)
        self.padding = k[0]
        self.value = k[1]

        self.data = data

    def pack(self):
        res = bytearray()
        res.extend(self.padding.to_bytes(1))
        res.extend(self.value.to_bytes(1))
        return res
    
    def spoof(self, allData = False):
        if allData:
            self.value = self.value ^ (2**8 - 2**self.padding)

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