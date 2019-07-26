#!/usr/bin/env python3
# 
# pycket: makes it ez to parse packets
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: GPL


from collections import OrderedDict 
from smartbytes import *
from pycket import *


def _parse(packet):
   pass 
    

def llmnr_parse(packet):
    root = PacketSegment(packet, name = 'root')
    
    parsed = root.parse_packet(OrderedDict({
        'dns.id' : {'size' : 2, 'unpack' : True},
        'dns.flags.tentative' : {'size' : 2, 'unpack' : True},
        'dns.count.queries' : {'size' : 2, 'unpack' : True},
        'dns.count.answers' : {'size' : 2, 'unpack' : True},
        'dns.count.auth_rr' : {'size' : 2, 'unpack' : True},
        'dns.count.add_rr' : {'size' : 2},
        'dns.qry.name' : {'count' : 'dns.count.queries', 'parse' : 'parse_multi_size', 'size' : 1},
        'dns.qry.type' : {'size' : 2},
        'dns.qry.class' : {'size' : 2}
    }))

if __name__ == '__main__':
    packet = smartbytes(unhexify(b'00010000000100000000000002343102343102343102343107696e2d61646472046172706100000c0001'))

    print(llmnr_parse(packet))
