from GoosePackage import GoosePackage
from scapy.all import *
# Handler is capable of dealing with signing and publishing messages
class GooseHandler:

    def __init__(self):
        self.package = GoosePackage()
        self.signMac = "assinar esse mac aqui"
        self.lastStNum = 0
        self.lastSqNum = 0

    def setPackage(self, pkg):
        if (isinstance(pkg, GoosePackage)):
            self.package = pkg
        else:
            print("YOU SET THE WRONG PACKAGE CLASS")

    def verifyEtherType(self):
        # TO DO: if package type is GOOSE.
        return False
    
    def verifyAddress(self):
        # Verify if signMac is the same destination mac from the Ethernet layer
        return True
    
    def publish(self):
        sendp(x=self.package.mountPackage(), iface="Ethernet")
        self.package.incrementSequence()
        return True

    def sign(self):
        return True