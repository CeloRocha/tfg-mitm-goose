from GooseHandler import GooseHandler
from GoosePackage import GoosePackage
from scapy.all import *
import time

START_TIME = time.time()
INTERVAL_TIME = 2.0

DATA = import_hexcap('0000  00 28 00 91 00 00 00 00  61 81 86 80 26 53 45 4c   ·(······ a···&SEL \n\
            0010  5f 32 34 31 34 5f 38 33  43 46 47 2f 4c 4c 4e 30   _2414_83 CFG/LLN0 \n\
            0020  24 47 4f 24 4e 65 77 47  4f 4f 53 45 4d 65 73 73   $GO$NewG OOSEMess \n\
            0030  61 67 65 81 02 07 d0 82  1e 53 45 4c 5f 32 34 31   age····· ·SEL_241 \n\
            0040  34 5f 38 33 43 46 47 2f  4c 4c 4e 30 24 4e 65 77   4_83CFG/ LLN0$New \n\
            0050  44 61 74 61 73 65 74 83  0b 53 45 4c 5f 32 34 31   Dataset· ·SEL_241 \n\
            0060  34 5f 38 33 84 08 65 2f  82 54 c7 ae 14 bf 85 01   4_83··e/ ·T······ \n\
            0070  01 86 01 09 87 01 00 88  01 01 89 01 00 8a 01 05   ········ ········ \n\
            0080  ab 0f 83 01 00 83 01 00  83 01 00 83 01 00 83 01   ········ ········ \n\
            0090  01                                                 ·')
SOURCE = "aa:bb:cc:dd:ee:ff"
DESTINATION = "01:0c:cd:01:00:33"

publisher = GooseHandler()
pkt = GoosePackage(DATA, SOURCE, DESTINATION)
publisher.setPackage(pkt)

while True:
    publisher.publish()
    time.sleep(INTERVAL_TIME - ((time.time() - START_TIME) % INTERVAL_TIME))