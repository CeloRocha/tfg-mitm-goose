from datetime import datetime
from scapy.all import *

class GoosePackage:

    def __init__(self, data = "", source = "", destination = ""):
        self.data = data
        self.stNum = 0
        self.sqNum = 0
        self.timeAllowedToLive: 1000
        self.t = datetime.now()
        self.source = source
        self.destination = destination
        self.type = 35000

    # NOT PRIVATE BECAUSE HACKERS WILL USE THAT
    def incrementSequence(self):
        self.sqNum += 1

     # NOT PRIVATE BECAUSE HACKERS WILL USE THAT
    def incrementState(self):
        self.stNum += 1
        self.sqNum = 0

    # Verify if the package is still able to be received
    def verifyAllowed(self):
        current_time = datetime.now()
        epoch_now = int(current_time.timestamp() * 1000)
        epoch_time = int(self.t.timestamp() * 1000)

        return epoch_now > epoch_time and epoch_now <= epoch_time + self.timeAllowedToLive
    
    # Get all package params in a form to be used by Scapy
    def mountPackage(self):
        return Ether(src=self.source, dst=self.destination, type=self.type)/self.data
    

    def decodePackage(self):
        # Get all 
        return 2
    
