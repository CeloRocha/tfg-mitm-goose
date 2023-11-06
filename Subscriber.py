from GoosePackage import GoosePackage
from scapy.all import *

# Handler is capable of dealing with signing and publishing messages
class Subscriber:

    def __init__(self, destination, type, iface, filter, callback = None):
        self.destination = destination
        self.type = type
        self.iface = iface
        self.filter = filter
        SOURCE = "aa:bb:cc:dd:ee:ff"
        DESTINATION = "01:0c:cd:01:00:33"
        self.package = GoosePackage('', SOURCE, DESTINATION)
        self.signMac = "assinar esse mac aqui"
        self.lastStNum = 0
        self.lastSqNum = 0

        if (callback == None or not callable(callback)):
            self.callback = self.__packet_callback
        else:
            self.callback = callback

    def setPackage(self, pkg):
        if (isinstance(pkg, GoosePackage)):
            self.package = pkg
        else:
            print("YOU SET THE WRONG PACKAGE CLASS")

    def getPackage(self):
        return self.package

    def verifyEtherType(self):
        # TO DO: if package type is GOOSE.
        return False
    
    def verifyAddress(self):
        # Verify if signMac is the same destination mac from the Ethernet layer
        return True

    def sign(self):
        return True

    def __packet_callback(self, packet):
        print(packet)
        encoded_array = bytearray(raw(packet[Ether].payload.load))

        hex_array : str = []
        for byte in encoded_array:
            hex_array.append(hex(byte))

        self.package.decodePackage(packet.load)

    def sniff(self):
        sniff(filter=self.filter, iface=self.iface, prn = self.callback, store=0)