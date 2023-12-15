from datetime import datetime
import time
from scapy.all import *
from DataTypes import *
from helper import *
from GoosePackage import GoosePackage

class HackedGoosePackage(GoosePackage):
    def spoof(self):
        for content in self.decodedData:
            content.spoof()
        return True

    def semantic(self):
        res = False
        if self.lastState:
            print("STATE", self.lastState != self.decodedData[self.dict['stNum']].getData())
            if self.lastState != self.decodedData[self.dict['stNum']].getData():
                res = True
        if self.lastState == None:
            res = True
        self.lastState = self.decodedData[self.dict['stNum']].getData()
        self.decodedData = self.firstPackage
        return res

    def highSequence(self):
        isSameSt = self.decodedData[self.dict['stNum']] == self.firstPackage[self.dict['stNum']]
        isSameSq = self.decodedData[self.dict['sqNum']] == self.firstPackage[self.dict['sqNum']]

        if isSameSt and isSameSq:
            self.decodedData[self.dict['sqNum']].to(4294967295)
        
        self.decodedData = self.firstPackage
        return False

    def highState(self):
        isSameSt = self.decodedData[self.dict['stNum']] == self.firstPackage[self.dict['stNum']]
        isSameSq = self.decodedData[self.dict['sqNum']] == self.firstPackage[self.dict['sqNum']]

        self.decodedData = self.firstPackage

        if isSameSt and isSameSq:
            self.firstPackage[self.dict['stNum']].to(4294967295 - 2)
            self.firstPackage[self.dict['sqNum']].to(0)
            return True
        else:
            return False

    def flooding(self):
        raise NotImplemented()