import idaapi 
import idautils
import idc

import os 

def memdump(ea, size, file):
    data = idc.GetManyBytes(ea, size)
    with open(file, "wb") as fp:
        fp.write(data)

file = "C:/1/1.bin"

memdump(0, 0x48, file)