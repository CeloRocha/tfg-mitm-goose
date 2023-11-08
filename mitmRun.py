from MITM import MITM 
from scapy.all import *
import sys, signal

def signal_handler(signal, frame):
    print("\nProgram interrupted")
    sys.exit(0)

#Exits loop
signal.signal(signal.SIGINT, signal_handler)

mitm = MITM(3)

mitm.sniff();