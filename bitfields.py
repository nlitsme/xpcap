# split value in bitfields 
#
#   bitfields(value, 1,2,3,4)
#   will return a list containing:    bit9, bit8-7, bit6-4, bit3-0
#
# list(bitfields(0x000000ff, 1,2,3,4))==[0, 1, 7, 15]
# list(bitfields(0x000003ff, 1,2,3,4))==[1, 3, 7, 15]
def bitfields(val, *bits):
    l= []
    for b in reversed(bits):
        mask= (1<<b)-1
        l.append(val & mask)
        val >>= b
    return reversed(l)

