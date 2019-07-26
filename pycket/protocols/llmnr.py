#!/usr/bin/env python3
# 
# llmnr: llmnr parser 
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: MIT (see LICENSE.md)


from collections import OrderedDict 
from smartbytes import *
from pycket import *

from . import arpa

class LLMNRPacketResponse(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'dns.id' : {'size' : 2, 'type' : 'u'},
            'dns.flags.tentative' : {'size' : 2, 'type' : 'u'},
            'dns.count.queries' : {'size' : 2, 'type' : 'u'},
            'dns.count.answers' : {'size' : 2, 'type' : 'u'},
            'dns.count.auth_rr' : {'size' : 2, 'type' : 'u'},
            'dns.count.add_rr' : {'size' : 2, 'type' : 'u'},
            'dns.qry.name' : {
                'count' : 'dns.count.queries',
                'parse' : 'parse_multi_size',
                'include' : True,
                'type' : arpa.ARPAPacketSegment,
                'size' : 1
            },
            'dns.qry.type' : {'size' : 2, 'type' : 'u'},
            'dns.qry.class' : {'size' : 2, 'type' : 'u'}
        })

if __name__ == '__main__':
    packet = LLMNRPacketResponse(unhexify('00010000000100000000000002343102343102343102343107696e2d61646472046172706100000c0001'))

    print(packet.__repr__)
