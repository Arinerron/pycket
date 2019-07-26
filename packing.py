#!/usr/bin/env python3
# 
# smartbytes: makes parsing bytes ez
# 
# Author: Aaron Esau <python@aaronesau.com>
# License: GPL
 

import binascii, struct, itertools
from smartbytes import *

to_bytes = lambda value, endian = 'big', encoding = 'utf-8' : value.encode(encoding = encoding) if isinstance(value, str) else (value.to_bytes(int((len(hex(value)) / 2) - 0.5), byteorder = E(endian)) if isinstance(value, int) else (value.get_contents() if isinstance(value, smartbytes) else (b''.join([to_bytes(x) for x in value]) if '__iter__' in dir(value) else value))) # i hope i don't have to debug this later...


e = lambda endian : ('<' if endian.strip().lower() in ['<', 'little'] else '>')
E = lambda endian : ('little' if endian.strip().lower() in ['<', 'little'] else 'big')

ul = lambda n : lambda x, endian = '>' : struct.unpack(e(endian) + n, x)[0]
pl = lambda n : lambda x, endian = '>' : struct.pack(e(endian) + n, x)

u8 = ul('b')
u16 = ul('H')
u32 = ul('I')
u64 = ul('Q')

p8 = pl('b')
p16 = pl('H')
p32 = pl('I')
p64 = pl('Q')

u = lambda data, endian = 'big', signed = False : int.from_bytes(bytes(to_bytes(data)), byteorder = endian, signed = signed)
p = lambda n, size = None, endian = 'big', signed = False : to_bytes(n.to_bytes(((n.bit_length() // 8) + 1 if size is None else size), byteorder = endian, signed = signed))
