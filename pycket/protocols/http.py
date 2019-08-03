#!/usr/bin/env python3
# 
# arpa: kinda weird i know
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: MIT (see LICENSE.md)


from collections import OrderedDict
from smartbytes import *
from pycket import *

import urllib.parse

class HTTPPathPacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'http.path' : {
                'parse' : 'parse_until',
                'char' : '?',
                'include' : False
            },

            'http.params' : {
                'size' : None, # until the end
                'post' : urllib.parse.parse_qs
            }
        })

class HTTPHeaderPacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'http.header.key' : {
                'parse' : 'parse_until',
                'char' : ':',
                'include' : False
            },

            'http.header.value' : {
                'size' : None,
                'post' : lambda x : x.lstrip()
            }
        })

class HTTPHeadersPacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'http.headers' : {
                'parse' : 'parse_until_split',
                'char' : ['\n', '\n\n'],
                'include' : False,
                'type' : HTTPHeaderPacketSegment
            }
        })

class HTTPRequestLinePacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'http.request.method' : {
                'parse' : 'parse_until',
                'char' : ' ',
                'include' : False
            },

            'http.request.uri' : {
                'parse' : 'parse_until',
                'char' : ' ',
                'include' : False,
                'type' : HTTPPathPacketSegment
            }
        })

class HTTPRequestPacketSegment(PacketSegment):
    def __init__(self, contents = b''):
        super().__init__(contents)

        self.mapping = OrderedDict({
            'http.request.line' : {
                'parse' : 'parse_until',
                'char' : '\n',
                'count' : 1,
                'include' : False,
                'type' : HTTPRequestLinePacketSegment
            },

            'http.headers' : {
                'parse' : 'parse_until',
                'char' : '\n\n',
                'include' : False,
                'type' : HTTPHeadersPacketSegment
            }
        })
