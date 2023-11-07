from datetime import datetime
import time
from scapy.all import *
from DataTypes import *
from helper import *

class GoosePackage:

    def __init__(self, data = "", source = "", destination = ""):
        self.data = data
        self.decodedData = None
        self.stNum = 0
        self.sqNum = 0
        self.timeAllowedToLive: 1000
        self.t = datetime.now()
        self.source = source
        self.destination = destination
        self.type = 35000
    
    def setSource(self, source):
        self.source = source

    def setDestination(self, destination):
        self.destination = destination

    def setType(self, type):
        self.type = type

    def __setTime(self):
        current_time = datetime.utcnow()
        t = time.time();
        # # ('Timestamp', (342940201L, 0L))
        # print("Set utc", current_time)
        # print("Set utc int", int(current_time.timestamp()))
        # print("Set utc sec", int(current_time.timestamp()/1000))
        # print("Set utc int", int(current_time.timestamp()*1000))
        self.decodedData[self.dict['t']].to(t) 

    # NOT PRIVATE BECAUSE HACKERS WILL USE THAT
    def incrementSequence(self):
        print("DATA: ",self.decodedData)
        print(self.dict['sqNum'])
        print(self.decodedData[self.dict['sqNum']])
        self.decodedData[self.dict['sqNum']].add(1)

     # NOT PRIVATE BECAUSE HACKERS WILL USE THAT
    def incrementState(self, max = False):
        if(max):
           self.decodedData[self.dict['stNum']].to(127)
        else:
           self.decodedData[self.dict['stNum']].add(1)
        self.decodedData[self.dict['sqNum']].to(0)
        self.__setTime()

    

    # Verify if the package is still able to be received
    def verifyAllowed(self):
        current_time = datetime.now()
        epoch_now = int(current_time.timestamp() * 1000)
        epoch_time = int(self.t.timestamp() * 1000)

        return epoch_now > epoch_time and epoch_now <= epoch_time + self.timeAllowedToLive
    
    def spoof(self):
        for content in self.decodedData:
            content.spoof()
        return self.decodedData

    def semantic(self):
        raise NotImplemented()

    def highSequence(self):
        self.decodedData[self.dict['sqNum']].to(4294967295 - 1)
    
    def highState(self):
        self.decodedData[self.dict['stNum']].to(4294967295 - 2)
        self.decodedData[self.dict['sqNum']].to(0)
    
    #  def flooding(self):
    #     raise NotImplemented()


    # Get all package params in a form to be used by Scapy
    def mountPackage(self):
        if self.decodedData:
            packed_data = bytearray()
            # packed_data = ''
            for content in self.decodedData:
                tag = struct.pack('!B', content.tag)
                package = content.pack()
                if len(package) < 128:
                    length = struct.pack('!B', len(package))
                else:  # HACK.. this will only support lengths up to 254.
                    length = struct.pack('!BB', 129, len(package))
                # packed_data += tag + length + package
                packed_data.extend(tag)
                packed_data.extend(length)
                packed_data.extend(package)

            leng = len(packed_data)
            size = 0x80
            if len(packed_data) < 256:
                leng = struct.pack('!B', len(packed_data))
                size = struct.pack('!B', 0x81) 
            else:
                leng = struct.pack('!BB', 129, len(packed_data))
                size = struct.pack('!B', 0x82) 
            k = struct.pack('!B', 97)
            print(k, size, leng)
            res = bytearray()
            res.extend(self.appId)
            res.extend((len(packed_data) + 10).to_bytes(2))
            res.extend(self.reserved1)
            res.extend(self.reserved2)
            res.extend(k)
            res.extend(size)
            res.extend(leng)
            res.extend(packed_data)
            self.data = res
        else:
            print("DO NOT HAVE", self.decodedData)
        return Ether(src=self.source, dst=self.destination, type=self.type)/self.data

    def decodePackage(self, load):

        # Get goose type and create data dictionary;
        # G


        self.appId = load[0:2]
        load=load[2:]

        #Tem que ser menor ou igual a 1492, está na norma! Implementar verificação
        length = load[0:2]
        load=load[2:]
        if int.from_bytes(length, byteorder='big') > 1492:
            print("Invalid GOOSE PDU Length")

        self.reserved1 = load[0:2]
        load=load[2:]

        self.reserved2 = load[0:2]
        load=load[2:]

        tag = load[0]
        load = load[1:]

        if tag != 0x61:
            print("Invalid GOOSE PDU")

        bytes_pdu_length = load[0] & 0x03
        load = load[1:]
        if bytes_pdu_length == 1:
            print("1 byte")
        elif bytes_pdu_length == 2:
            print("2 bytes")
        else:
            print("Bytes: ", bytes_pdu_length)
        

        pdu_length = load[0:bytes_pdu_length]
        # print(pdu_length)
        load = load[bytes_pdu_length:]

        tagmap = {128:('gocbRef', VisibleString), 
              129:('timeAllowedToLive', Integer), 
              130:('datSet', VisibleString), 
              131:('goID', VisibleString),
              132:('t', UTCTime), 
              133:('stNum', Integer),
              134:('sqNum', Integer), 
              135:('test',Boolean),
              136:('confRev', Integer), 
              137:('ndsCom', Boolean),
              138:('numDataSetEntries', Integer),
              171:('allData', Data)}

        self.decodedData = decoder(load, tagmap)
        self.dict = {}
        
        for index, item in enumerate(self.decodedData):
            self.dict[item.name] = index

        # print(self."appid: ", appid)
        # print("length: ", length)
        # print("reserved1: ", reserved1)
        # print("reserved2: ", reserved2)
        # print("bytesPduLength: ", bytes_pdu_length)
    