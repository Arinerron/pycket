#!/usr/bin/env python3
# 
# arpa: kinda weird i know
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: MIT (see LICENSE.md)


from collections import OrderedDict 
from smartbytes import *
from pycket import *

def from_arpa(address):
    return '.'.join(reversed([str(x) for x in address[:-2]])) 

def to_arpa(address):
    return address

class ARPAPacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'arpa.address' : {
                'parse' : 'parse_multi_size',
                'post' : from_arpa,
                'size' : 1
            },
        })

if __name__ == '__main__':
    packet = LLMNRPacket(unhexify('00010000000100000000000002343102343102343102343107696e2d61646472046172706100000c0001'))

    print(packet.__repr__)

