from MITM import MITM 
from scapy.all import *
import sys, signal

def signal_handler(signal, frame):
    print("\nProgram interrupted")
    sys.exit(0)

#Exits loop
signal.signal(signal.SIGINT, signal_handler)

# Spoof: 0
# High Sequence: 1
# High State: 2
# Semantic: 3
mitm = MITM()
print("RUN")
mitm.sniff();