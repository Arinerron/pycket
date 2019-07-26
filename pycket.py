#!/usr/bin/env python3
# 
# pycket: makes it ez to parse packets
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: GPL


from collections import OrderedDict 
from smartbytes import *


class PacketSegment(smartbytes):
    def __init__(self, parent, name = 'data', offset = 0, size = None, contents = b''):
        super().__init__(contents)

        if size is None:
            size = len(parent)

        self._parent = parent
        self._name = name
        self._offset = offset
        self._size = size
        self._children = []

    # getters

    def get_parent(self):
        return self._parent

    def get_name(self):
        return self._name

    def get_offset(self):
        return self._offset
    
    def get_size(self):
        return self._size

    def get_children(self):
        return self._children

    # misc functions

    def get_value(self):
        return self.get_contents()
        #return self._parent[self._offset : self._offset + self._size]

    # parsing functions

    '''
    returns the bytes from `offset` to `size`
    '''
    def parse(self, offset = 0, size = None):
        return self.get_value()[offset : (None if size is None else offset + size)]

    '''
    parses bytes until `count` `char` characters are found, starting at `offset`
    '''
    def parse_until(self, offset = 0, char = '\x00', count = 1, include = True):
        build = smartbytes()

        for byte in self.parse(offset):
            if byte == char:
                count -= 1

            if count == 0:
                if include == True:
                    build += byte

                break
            
            build += byte

        return build

    '''
    parses the first n bytes defined by a header of `size_size` bytes, starting at `offset` (or `offset` + `size_size` if `include`)
    '''
    def parse_size(self, offset = 0, size_size = 1, include = True):
        build = smartbytes()
        size = u(self.parse(offset, size_size))

        if include:
            offset += size_size
        else:
            size += size_size
        
        return self.parse(offset, size = size)
    
    def parse_multi_size(self, offset = 0, size_size = 1, char = '\x00', include = True):
        build = []

        while True:
            segment = self.parse_size(offset = offset, size_size = size_size, include = False)
            size = len(segment)
            
            if include:
                segment = p(size, size = size_size) + segment

            build.append(segment)

            offset += size_size + size

            if self.parse(offset, len(char)) == char or offset > len(self):
                break

        return build

    def parse_packet(self, mapping):
        parsed = OrderedDict()

        offset = 0

        for key in mapping:
            value = mapping[key]

            size = value.get('size', 1)
            unpack = value.get('unpack', False)
            parse = value.get('parse', 'parse').strip().lower()
            count = value.get('count', None)

            for i in range(1 if count is None else (count if isinstance(count, int) else u(count))):
                output = None

                include = value.get('include', False)
                char = value.get('char', '\x00')

                if parse == 'parse_multi_size':
                    output = self.parse_multi_size(offset = offset, size_size = size, char = char, include = include)

                    offset += len(char)

                    if not include:
                        offset += (len(output) * size)

                    offset += len(smartbytes().join(output))
                elif parse == 'parse_size':
                    output = self.parse_size(offset = offset, size_size = size, include = include)

                    if not include:
                        offset += size

                    offset += len(output)
                elif parse == 'parse_until':
                    output = self.parse_until(offset = offset, char = char, count = value.get('count', 1), include = include)

                    if not include:
                        offset += len(char)

                    offset += len(output)
                else:
                    output = self.parse(offset = offset, size = size)

                    offset += len(output)

                # build up a list if count
                if count is None:
                    parsed[key] = output
                else:
                    if not key in parsed:
                        parsed[key] = list()

                    parsed[key].append(output)

        print(parsed)
        return parsed

