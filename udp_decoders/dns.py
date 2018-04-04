import struct
from bitfields import bitfields

#todo: decode addrs in rrdata

# decode DNS messages

class DNSPacket:
    rrtypes= {
        1:"A",   #  4 byte addr
        2:"NS",  #  name
        3:"MD",
        4:"MF",
        5:"CNAME",#  name
        6:"SOA",  #  name, name, L:Serial, L:Refresh, L:Retry, L:Expire, L:Minimum
        7:"MB",
        8:"MG",
        9:"MR",
        10:"NULL",
        11:"WKS",
        12:"PTR",# name
        13:"HINFO",
        14:"MINFO",
        15:"MX",
        16:"TXT",  # B:len,  <text>
        17:"RP",
        18:"AFSDB",
        19:"X25",
        20:"ISDN",
        21:"RT",
        22:"NSAP",
        23:"NSAP-PTR",
        24:"SIG",
        25:"KEY",
        26:"PX",
        27:"GPOS",
        28:"AAAA",   # 16 byte addr
        29:"LOC",
        30:"NXT",
        31:"EID",
        32:"NIMLOC",
        33:"SRV",     # H:prio, H:weight, H:port   name  
        34:"ATMA",
        35:"NAPTR",
        36:"KX",
        37:"CERT",
        38:"A6",
        39:"DNAME",
        40:"SINK",
        41:"OPT",
        42:"APL",
        43:"DS",
        44:"SSHFP",
        45:"IPSECKEY",
        46:"RRSIG",
        47:"NSEC",
        48:"DNSKEY",
        49:"DHCID",
        50:"NSEC3",
        51:"NSEC3PARAM",
        52:"TLSA",
#53-54:"Unassigned",
        55:"HIP",
        56:"NINFO",
        57:"RKEY",
        58:"TALINK",
        59:"CDS",
        60:"CDNSKEY",
        61:"OPENPGPKEY",
        62:"CSYNC",
#63-98:"Unassigned",
        99:"SPF",
        100:"UINFO",
        101:"UID",
        102:"GID",
        103:"UNSPEC",
        104:"NID",
        105:"L32",
        106:"L64",
        107:"LP",
        108:"EUI48",
        109:"EUI64",
#110-248:"Unassigned",
        249:"TKEY",
        250:"TSIG",
        251:"IXFR",
        252:"AXFR",
        253:"MAILB",
        254:"MAILA",
        255:"*",
        256:"URI",
        257:"CAA",
#258-32767:"Unassigned",
        32768:"TA",
        32769:"DLV",
#32770-65279:"Unassigned",
#65280-65534:"Private use",
        65535:"Reserved",
    }
    reqopcodes= {
        0:"query",
        1:"iquery",
        2:"status",
        4:"notify",
        5:"update",
    }
    responsecodes= {
        0:"ok",
        1:"format error",
        2:"serverfailure",
        3:"nameerror",
        4:"notimplemented",
        5:"refused",
    }
    @staticmethod
    def parse_name(pkt, ofs, last):
        #print "pn @%d" % ofs
        name= []
        while ofs<last:
            h= ord(pkt[ofs])
            ofs += 1
            if h==0:
                break
            elif h<64: # name element
                name.append(pkt[ofs:ofs+h])
                ofs += h
            elif h>=0xc0: # name ptr 
                o= ord(pkt[ofs]) | (h&0x3f)<<8
                ofs += 1
                n, o= DNSPacket.parse_name(pkt, o, last)
                name += n
                break  # never continue after ptr
            else:
                print("WARNING: unsupported label type: %02x" % h)
        return name, ofs
    @staticmethod
    def parse_text(pkt, ofs, last):
        lines= []
        while ofs<last:
            l= ord(pkt[ofs])
            ofs += 1
            lines.append(pkt[ofs:ofs+l])
            ofs += l
        return "\n".join(lines)

    @staticmethod
    def decodename(n):
        return ".".join(n)
    @staticmethod
    def rrclassname(cls):
        if cls==1: return "IN"
        if cls==3: return "CH"
        if cls==4: return "HS"
        if cls==254: return "NONE"
        if cls==255: return "ANY"
        return "cls:"+str(cls)
    @staticmethod
    def rrtypename(typ, cls):
        if typ in DNSPacket.rrtypes:
            n= DNSPacket.rrtypes[typ]
        else:
            n= "rr:"+str(typ)
        if cls==1:
            return n
        else:
            return DNSPacket.rrclassname(cls)+":"+n

    @staticmethod
    def opcodename(op):
        if op in DNSPacket.reqopcodes:
            return DNSPacket.reqopcodes[op]
        return "op:"+str(op)

    @staticmethod
    def responsename(op):
        if op in DNSPacket.responsecodes: 
            return DNSPacket.responsecodes[op]
        return "err:"+str(op)

    @staticmethod
    def decode_rdata(pkt, typ, ofs, last):
        if typ in (1,28):  # raw address
            return pkt[ofs:last].encode("hex")
        if typ in (2, 5, 12):   # name
            n, ofs= DNSPacket.parse_name(pkt, ofs, last)
            return n
        if typ==6: # SOA
            mname, ofs= DNSPacket.parse_name(pkt, ofs, last)
            rname, ofs= DNSPacket.parse_name(pkt, ofs, last)
            serial, refresh, retry, expire, minimum= struct.unpack_from(">LLLLL", pkt, ofs)
            ofs += 20
            return (mname, rname, serial, refresh, retry, expire, minimum)
        if typ==16: # TXT
            return DNSPacket.parse_text(pkt, ofs, last)
        if typ==33: # SRV
            prio, weight, port= struct.unpack_from(">HHH", pkt, ofs)
            ofs += 6
            name, ofs= DNSPacket.parse_name(pkt, ofs, last)
            return (prio, weight, port, name)
        if typ==41: # OPT
            opt= []
            while ofs+4<=last:
                otyp, olen= struct.unpack_from(">HH", pkt, ofs)      ; ofs += 4
                opt.append((otyp, pkt[ofs:ofs+olen].encode("hex")))
                ofs += olen
            return opt
        if typ==47: # NSEC
            flags, proto, alg= struct.unpack_from(">HBB", pkt, ofs)  ; ofs += 2
            return (flags, proto, alg, pkt[ofs:])

        # 10 NULL
        print("unknown rrtype: %d" % typ)
        return pkt[ofs:last]
    class RRecord:
        @classmethod
        def parse(cls, pkt, ofs, last):
            #print "rr @%d" % ofs
            rec= cls()
            rec.name, ofs= DNSPacket.parse_name(pkt, ofs, last)
            rec.rtype, rec.rclass, rec.ttl, rdlen= struct.unpack_from(">HHLH", pkt, ofs)
            ofs += 10
            rec.rdata= DNSPacket.decode_rdata(pkt, rec.rtype, ofs, ofs+rdlen)
            ofs += rdlen
            return rec, ofs
        def __str__(rec):
            r= rec.rdata
            return "%s  %s,%d  %s" % (DNSPacket.decodename(rec.name), DNSPacket.rrtypename(rec.rtype, rec.rclass), rec.ttl, r)
    class Question:
        @classmethod
        def parse(cls, pkt, ofs, last):
            #print "q @%d" % ofs
            rec= cls()
            rec.name, ofs= DNSPacket.parse_name(pkt, ofs, last)
            rec.qtype, rec.qclass= struct.unpack_from(">HH", pkt, ofs)
            ofs += 4
            return rec, ofs
        def __str__(rec):
            return "%s  %s ?" % (DNSPacket.decodename(rec.name), DNSPacket.rrtypename(rec.qtype, rec.qclass))

    @staticmethod
    def parse(pkt, ofs, last):
        dns= DNSPacket()
        ident, flags, qdcount, ancount, nscount, arcount= struct.unpack_from(">HHHHHH", pkt, ofs)
        ofs += 12
        dns.ident= ident
        dns.isresponse, dns.opcode, dns.authoritative, dns.truncated, dns.recursive_query, dns.recursion_available, dns.reserved_bits, dns.response_code= bitfields(flags, 1,4,1,1,1,1,3,4)

# http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
# opcode: 0=standard query, 1=inverse query, 2=status request, 4=notify, 5=update
# responsecode: 0=ok, 1=format error, 2=serverfailure, 3=nameerror, 4=notimplemented, 5=refused

        dns.questions, ofs= DNSPacket.readrecords(DNSPacket.Question, qdcount, pkt, ofs, last)
        dns.answers, ofs= DNSPacket.readrecords(DNSPacket.RRecord, ancount, pkt, ofs, last)
        dns.authoritatives, ofs= DNSPacket.readrecords(DNSPacket.RRecord, nscount, pkt, ofs, last)
        dns.additionals, ofs= DNSPacket.readrecords(DNSPacket.RRecord, arcount, pkt, ofs, last)

        return dns, ofs

    @staticmethod
    def readrecords(typ, count, pkt, ofs, last):
        #print "readrecs @%d" % ofs
        l= []
        while count>0:
            rec, ofs= typ.parse(pkt, ofs, last)
            l.append(rec)
            count -= 1
        return l, ofs


    def __str__(dns):
        r= []
        r += ("%04x" % dns.ident,)
        r += ("resp" if dns.isresponse else "query",)
        r += (DNSPacket.opcodename(dns.opcode), )
        if dns.authoritative: r += ("auth",)
        if dns.truncated: r += ("trunc",)
        if dns.recursive_query: r += ("rquery",)
        if dns.recursion_available: r += ("ravail",)
        if dns.reserved_bits: r += ("res:%d",)
        r += (DNSPacket.responsename(dns.response_code), )

        r= " ".join(r) + "\n"

        if dns.questions:
            r += "--%d questions\n" % len(dns.questions)
        for q in dns.questions:
            r += "    " + str(q)+"\n"

        if dns.answers:
            r += "--%d answers\n" % len(dns.answers)
        for q in dns.answers:
            r += "    " + str(q)+"\n"

        if dns.authoritatives:
            r += "--%d authorotives\n" % len(dns.authoritatives)
        for q in dns.authoritatives:
            r += "    " + str(q)+"\n"

        if dns.additionals:
            r += "--%d additionals\n" % len(dns.additionals)
        for q in dns.additionals:
            r += "    " + str(q)+"\n"
        return r

toplevel=DNSPacket
