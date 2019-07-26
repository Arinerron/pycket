import protocols.llmnr as llmnr
from pycket import *

print(llmnr.LLMNRPacketResponse(unhexify('00010000000100000000000002343102343102343102343107696e2d61646472046172706100000c0001')))
