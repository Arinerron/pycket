# About

pycket makes packet parsing simple

# Install

The only requirement other than any version of `python3` is [`smartbytes`](https://github.com/Arinerron/smartbytes).

```
git clone https://github.com/Arinerron/pycket.git
cd pycket

sudo python3 setup.py install
```

# Documentation

Coming soon.

# Examples

```
from pycket import *

# decode a hex-encoded LLMNR response packet
packet = unhexify('00010000000100000000000002343102343102343102343107696e2d61646472046172706100000c0001')

# parse it
parsed_packet = llmnr.LLMNRPacketResponse(packet)

# print it
print(parsed_packet)
```
