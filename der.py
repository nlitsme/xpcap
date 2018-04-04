
# get tag+length+value from BER encoded data
def gettlv(data, first, last):
    #print "%04x-%04x: " % (first, last),
    ofs= first
    if ofs+2>last:
        return
    t= ord(data[ofs]) ; ofs += 1
    # bit76: class: 00=univ, 01=app, 10=cont, 11=priv
    # bit5 : 0=primitive, 1=constructed
    cls= t>>6
    cons= (t>>5)&1


    # 00: end of construct
    # 01: boolean
    # 02: integer
    # 03: bit string: first byte: nr unused bits
    # 04: octet string
    # 05: NULL
    # 06: object
    # 07: objdescriptor
    # 08: externaltype
    # 09: real
    # 0a: enum
    # 0b: embedded
    # 0c: utf8string
    # 0d: relativeoid
    # 0e
    # 0f
    # 10: sequence
    # 11: set
    # 12: NumericString
    # 13: PrintableString
    # 14: T61String
    # 15: VideoTexString
    # 16: IA5String
    # 17: timestamp
    # 18
    # 19: GraphicString
    # 1a: VisibleString
    # 1b: GeneralString
    # 1c: UniversalString
    # 1d: UnrestrictedString
    # 1e: BMPString

    tag= t&0x1F
    if tag==0x1F:
        # long tag
        tag=0
        while True:
            t= ord(data[ofs]) ; ofs += 1
            tag = (tag<<7) | (t&0x7F)
            if (t&0x80)==0:
                break

    l= ord(data[ofs]) ; ofs += 1
    if l==0x80:
        # indefinite length
        # terminated by (00,00) - EOC tag
        return tag, ofs, None

    if l>0x80:
        # long length
        n= l&0x7F
        if ofs+n>last:
            return
        l= 0
        while n>0:
            l <<= 8
            l += ord(data[ofs]) ; ofs += 1
            n -= 1
    if ofs+l>last:
        return
    #print "%02x  %04x-%04x" % (t, ofs, ofs+l)
    return cls, cons, tag, ofs, ofs+l

# get specific item from a DER encoded object,
#   path specifies which path in the asn1 object tree to walk.
#    negative numbers specify a specific CONTEXT item
#    positive numbers specify the specific non-CONTEXT item in order found.
# data is the actual data containing the DER object
# (first,last)  are indexes into the data string
def get(path, data, first, last):
    if len(path)==0:
        return first, last
    ofs= first
    item= path[0]
    if item<0:
        # context item
        while ofs < last:
            cls, cons, tag, d0,d1= gettlv(data, ofs, last)
            if cls==2 and tag == -(item+1):
                return get(path[1:], data, d0, d1)
            ofs= d1
        # not found
        return None

    # universal item
    while item>0 and ofs < last:
        cls, cons, tag, d0,d1= gettlv(data, ofs, last)
        if cls==0:
            item -= 1
        ofs= d1

    # skip non-universal items
    while item==0 and ofs < last:
        cls, cons, tag, d0,d1= gettlv(data, ofs, last)
        if cls==0:
            return get(path[1:], data, d0, d1)
        ofs= d1

# iterate over all DER items in the (first,last) range
def iter(data, first, last):
    ofs= first
    while ofs<last:
        cls, cons, tag, d0, d1= gettlv(data, ofs, last)
        yield cls, cons, tag, d0, d1
        ofs= d1

