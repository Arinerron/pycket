#!/usr/bin/env python3
# 
# pycket: makes it ez to parse packets
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: MIT (see LICENSE.md)


from collections import OrderedDict 
from smartbytes import *

class PacketSegment(smartbytes):
    def __init__(self, contents = b'', mapping = {}):
        self.mapping = mapping

        super().__init__(contents)

    # misc functions

    def get_mapping(self, key = None):
        if not key is None:
            return self.get_mapping().get(key, {})

        return self.mapping

    def __str__(self, data = None, indent = 1, size = 2):
        build = ''
        
        segment_indent = 2
        
        if data is None:
            data = self.parse()
            build += '\n%s<segment type=%s>\n' % (' ' * indent, self.__class__.__name__)
            indent += segment_indent

        if isinstance(data, PacketSegment):
            build += '%s<segment type=%s>\n' % (' ' * indent, data.__class__.__name__)
            indent += segment_indent
            data = data.parse()
        elif isinstance(data, smartbytes):
            #build += '%s* ' % (' ' * indent) + data.human()
            #return build
            data = [data]

        for key in data:
            if isinstance(data, dict) or isinstance(data, OrderedDict):
                value = data[key]
            else:
                value = key
                key = None

            if not key is None:
                build += '%s* %s: ' % (' ' * indent, key)
            else:
                build += '%s* ' % (' ' * indent)

            if isinstance(value, dict) or isinstance(value, OrderedDict) or (isinstance(value, PacketSegment) and not value is self):
                build += '\n' + self.__str__(data = data, indent = indent + size, size = size)
                continue
            if isinstance(value, smartbytes):
                build += value.human() + '\n'
                continue
            if isinstance(value, list) or isinstance(value, set):
                build += '\n' + (''.join([self.__str__(data = x, indent = indent + size, size = size) for x in value]))
                continue

            if isinstance(value, bytes):
                build += str(value)[1:]
            else:
                build += str(value)

            build += '\n'

        return build.rstrip('\n') + '\n'

        

    # parsing functions

    '''
    wrapper
    '''
    def parse(self):
        return self._parse_packet()[1]

    '''
    returns the bytes from `offset` to `size`
    '''
    def _parse(self, offset = 0, size = None):
        return smartbytes(self.get_contents()[offset : (None if size is None else offset + size)])

    '''
    parses bytes until `count` `char` characters are found, starting at `offset`
    '''
    def _parse_until(self, offset = 0, char = '\x00', count = 1, include = True):
        build = smartbytes()

        for byte in self._parse(offset):
            if byte == char:
                count -= 1

            if count == 0:
                if include == True:
                    build += byte

                break
            
            build += byte

        return build

    '''
    parses bytes until `char[0]` is found, splitting on `char[1]` or "\n"
    '''
    def _parse_until_split(self, offset = 0, char = ['\n', '\n\n'], include = True):
        output = list()

        for byteslist in self._parse(offset).partition(char[1])[0].split(char[0]):
            if include:
                byteslist += char[0]

            output.append(byteslist)
    
        return output

    '''
    parses the first n bytes defined by a header of `size_size` bytes, starting at `offset` (or `offset` + `size_size` if `include`)
    '''
    def _parse_size(self, offset = 0, size_size = 1, include = True):
        build = smartbytes()
        size = u(self._parse(offset, size_size))

        if include:
            size += size_size
        else:
            offset += size_size
        
        return self._parse(offset, size = size)
    
    def _parse_multi_size(self, offset = 0, size_size = 1, char = '\x00', include = True, dtype = None, deep = False):
        build = []

        char = smartbytes(char)

        while True:
            segment = self._parse_size(offset = offset, size_size = size_size, include = False)
            size = len(segment)
            
            if include:
                segment = p(size, size = size_size) + segment

            build.append(segment)

            offset += size_size + size
            
            if self._parse(offset, len(char)) == char:
                if include and len(build) != 0:
                    build[-1] += bytes(char)
                
                break
            if offset > len(self):
                break
        
        output = list()
        
        for x in build:
            output.append(self._parse_dtype(x, dtype, deep = deep))

        return output
        
    def _parse_dtype(self, output, dtype, deep = False):
        # parse if a subsegment is specified
        if not dtype is None:
            if isinstance(dtype, type.__class__) and isinstance(dtype(), PacketSegment):
                output = dtype(smartbytes(output))

                if deep:
                    output = output.parse(deep = deep)
            else:
                if isinstance(dtype, str):
                    dtype = dtype.strip().lower()

                if dtype in [int, 'int']:
                    try:
                        output = int(bytes(smartbytes(0 if len(output) == 0 else output))) # TODO: if(alnum(bytes(smartbytes(output)))) then unpack first?
                    except:
                        # TODO: warn instead of silently fail?
                        pass
                elif dtype in ['unpack', 'u', 'up']:
                    output = u(output) # TODO: allow specifying unpack size
                elif dtype in [bool, 'bool', 'boolean']:
                    output = bool(output)
                elif dtype in [smartbytes, str, bytes, 'str', 'bytes', 'smartbytes']:
                    output = smartbytes(output)
        elif isinstance(output, bytes):
            output = smartbytes(output)
        
        return output

    def _parse_packet(self, deep = False):
        parsed = OrderedDict()

        offset = 0

        for key in self.get_mapping():
            value = self.get_mapping(key)

            size = value.get('size', 1)
            dtype = value.get('type', None)
            count = value.get('count', None)
            parse = value.get('parse', 'parse')
            include = value.get('include', False)
            char = value.get('char', '\x00')
            post = value.get('post', None)

            if isinstance(parse, str):
                parse = parse.strip().lower()

            if (not count is None) and (not key in parsed):
                parsed[key] = list()

            for i in range(1 if count is None else (count if isinstance(count, int) else u(parsed[count]))):
                output = None

                if not isinstance(parse, str):
                    size, output = parse(self._parse(offset = offset, size = size))._parse_packet()
                    
                    offset += len(output)
                elif parse == 'parse_multi_size':
                    output = self._parse_multi_size(offset = offset, size_size = size, char = char, include = include, dtype = dtype, deep = deep)

                    offset += len(char)

                    if not include:
                        offset += (len(output) * size)

                    offset += len(smartbytes().join(output))
                elif parse == 'parse_size':
                    output = self._parse_size(offset = offset, size_size = size, include = include)

                    if not include:
                        offset += size

                    offset += len(output)
                elif parse == 'parse_until':
                    output = self._parse_until(offset = offset, char = char, count = value.get('count', 1), include = include)

                    if not include:
                        offset += len(char)

                    offset += len(output)
                elif parse == 'parse_until_split':
                    output = self._parse_until_split(offset = offset, char = char, include = include)

                    if not include:
                        offset += len(char[1])

                    offset += len(smartbytes(char[0]).join(output))
                else:
                    output = self._parse(offset = offset, size = size)

                    offset += len(output)

                if not isinstance(output, list): # could cause issues TODO investigate
                    output = [output]
                
                for seg in output:
                    output = self._parse_dtype(seg, dtype, deep = deep)

                if not post is None:
                    if not isinstance(post, list):
                        post = [post]
                    
                    for function in post:
                        output = function(output)
                
                # build up a list if count
                if count is None:
                    parsed[key] = output
                else:
                    parsed[key].append(output)

        return (offset, parsed)

