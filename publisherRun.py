from Publisher import Publisher
from GoosePackage import GoosePackage
from scapy.all import *
import time

START_TIME = time.time()
INTERVAL_TIME = 1.0

DATA = import_hexcap('0000  00 10 00 98 00 00 00 00  61 81 8d 80 22 53 45 4c   ········ a···"SEL\n\
0010  5f 37 30 30 47 5f 31 43  46 47 2f 4c 4c 4e 30 24   _700G_1C FG/LLN0$\n\
0020  47 4f 24 47 4f 4f 53 45  4d 65 73 73 61 67 65 81   GO$GOOSE Message·\n\
0030  02 07 d0 82 1c 53 45 4c  5f 37 30 30 47 5f 31 43   ·····SEL _700G_1C\n\
0040  46 47 2f 4c 4c 4e 30 24  47 4f 4f 53 45 44 53 65   FG/LLN0$ GOOSEDSe\n\
0050  74 83 0a 53 45 4c 5f 37  30 30 47 5f 31 84 08 65   t··SEL_7 00G_1··e\n\
0060  4a 4c 7e 06 66 66 bf 85  01 05 86 02 00 00 87 01   JL~·ff·· ········\n\
0070  00 88 01 01 89 01 00 8a  01 05 ab 1c 83 01 00 84   ········ ········\n\
0080  02 06 40 87 05 08 00 00  00 00 87 05 08 00 00 00   ··@····· ········\n\
0090  00 87 05 08 00 00 00 00                            ········')
SOURCE = "aa:bb:cc:dd:ee:ff"
DESTINATION = "01:0c:cd:01:00:33"

pkg = GoosePackage(DATA, SOURCE, DESTINATION)
pkg.decodePackage(bytearray(raw(DATA)))
publisher = Publisher(pkg)

while True:
    publisher.publish()
    time.sleep(INTERVAL_TIME - ((time.time() - START_TIME) % INTERVAL_TIME))