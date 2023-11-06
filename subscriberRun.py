from Subscriber import Subscriber 
from scapy.all import *
import sys, signal

DESTINATION = "01:0c:cd:01:00:33"
TYPE = 35000
IFACE = "Ethernet"
FILTER = "ether proto 35000"

def signal_handler(signal, frame):
    print("\nProgram interrupted")
    sys.exit(0)

#Exits loop
signal.signal(signal.SIGINT, signal_handler)

# def chora(packet):
#     print("CHEGOU SINAL")

subscriber = Subscriber(DESTINATION, TYPE, IFACE, FILTER)

while True:
    subscriber.sniff();