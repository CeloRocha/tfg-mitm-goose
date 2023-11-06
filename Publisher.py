from GoosePackage import GoosePackage
from scapy.all import *
import time

# Handler is capable of dealing with signing and publishing messages
class Publisher:

    def __init__(self, package = GoosePackage()):
        self.package = package
        self.signMac = "assinar esse mac aqui"
        self.lastStNum = 0
        self.lastSqNum = 0

    def setPackage(self, pkg):
        if (isinstance(pkg, GoosePackage)):
            self.package = pkg
        else:
            print("YOU SET THE WRONG PACKAGE CLASS")
    
    def publish(self):
        sendp(x=self.package.mountPackage(), iface="Ethernet")
        self.package.incrementSequence()
        return True

    def publishEvent(self):
        sTime = time.time()
        self.package.incrementState()
        self.publish()
        time.sleep(0.004 - ((time.time() - sTime) % 0.004))
        self.publish()
        time.sleep(0.004 - ((time.time() - sTime) % 0.004))
        self.publish()