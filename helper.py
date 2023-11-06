import struct 
from DataTypes import *

class DecoderError(Exception):
    pass

def unpack_varint(data, length):
    """ Decodes a variable length integer """
    if length == 1: 
        data = struct.unpack('!h', '\x00' + data)[0]
    elif length == 2:
        data = struct.unpack('!h', data)[0]
    elif length == 4:
        data = struct.unpack('!i', data)[0]
    else:
        data = -1
    return data

def hack(data):
    for content in data:
        content.hack()
    return data

def encoder(data):
    packed_data = ''

    for content in data:
        tag = struct.pack('!B', content.tag)
        package = content.pack()
        if len(package) < 128:
            length = struct.pack('!B', len(package))
        else:  # HACK.. this will only support lengths up to 254.
            length = struct.pack('!BB', 129, len(package))
        packed_data += tag + length + package

    return packed_data


def decoder(data, tagmap, ignore_errors=True, decode_as_list=True):
    """ Decodes binary data encoded in a BER format and return a dictonary.

    Keyword Arguments:
    data -- the binary data to decode stored in a string
    tagmap -- a dictionary keyed by a tag tuple (class, format, id) as integer
              values with tuple values (name, type).
    ignore_errors -- will cause the decoder to skip past errors and continue

    """
    # if decode_as_list:
    results = list()
    # else:
    #     results = dict()

    while len(data) > 0:

        tag = data[0]
        length = data[1]
        value = data[2:2+length]
        data = data[2+length:]

        try:
            name = tagmap[tag][0]
            inst = tagmap[tag][1]
            val = inst(value, length) # exception handling?
            val.tag = tag
            val.name = name
            results.append(val)
            # print(val.tag, ", ", name, ": ", val)
        except KeyError:
            if ignore_errors:
                print('Unfound tag %s' % tag)
                continue
            else:
                raise DecoderError("Tag not found in tagmap, %s", tag)
   
        # if decode_as_list:
        
        # else:
        #     results[name] = val

    print("results ", results)
    return results
    
def float_to_binary(x):
    """Convert the float value x to a binary string of length m + n
    where the first m binary digits are the integer part and the last
    'n' binary digits are the fractional part of x.
    """
    
    x_scaled = round(x * 2**24)
    return '{:0{}b}'.format(x_scaled, 32 + 24)

def binary_to_float(bstr):
    """Convert a binary string in the format given above to its float
    value.
    """
    return int(bstr, 2) / 2**24

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])
