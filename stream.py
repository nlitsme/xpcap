from __future__ import print_function
import pkgutil
import stream_decoders
# this module decodes stream based protocols.
# and resolves retransmissions.

decoders= []

# __path__ is used to find the location of all decoder submodules
for impimp, name, ii in pkgutil.iter_modules(stream_decoders.__path__):
    impload= impimp.find_module(name)
    decoders.append(impload.load_module(name).toplevel)

import math
import time
import struct

def addrstring(*args):
    if len(args)==1 and type(args[0])==tuple:
        # from getaddr
        args= args[0]
    if len(args)==0:
        raise Exception("no addr")
    addr= args[0]
    if len(addr)==4:
        addr= ".".join(map(lambda x:str(x),  struct.unpack("4B", addr)))
    elif len(addr)==16:
        addr= ":".join(map(lambda x:"%04x"%x if x else "",  struct.unpack(">8H", addr)))
    else:
        raise Exception("invalid addr")
    if len(args)==1:
        return addr
    elif len(args)==2:
        return addr+"."+str(args[1])
    else:
        raise Exception("addr: too many items")

def getaddr(ctx, frm):
    # ipaddr
    if hasattr(ctx, frm):
        return getattr(ctx, frm)

    # ipaddr + portnum
    for proto in ("udp", "tcp"):
        if hasattr(ctx, proto):
            return getattr(ctx.ip, frm), getattr(getattr(ctx, proto), frm)
    # ipaddr
    return getattr(ctx.ip, frm)

def pkttag(ip, p):
    if p.src < p.dst:
        return "%s:%s" % (addrstring(ip.dst, p.dst), addrstring(ip.src, p.src))
    elif p.src > p.dst:
        return "%s:%s" % (addrstring(ip.src, p.src), addrstring(ip.dst, p.dst))
    elif ip.src < ip.dst:
        return "%s:%s" % (addrstring(ip.dst, p.dst), addrstring(ip.src, p.src))
    else:
        return "%s:%s" % (addrstring(ip.src, p.src), addrstring(ip.dst, p.dst))

def pktprefix(ip, p):
    if p.src < p.dst:
        return "%s < %s" % (addrstring(ip.dst, p.dst), addrstring(ip.src, p.src))
    elif p.src > p.dst:
        return "%s > %s" % (addrstring(ip.src, p.src), addrstring(ip.dst, p.dst))
    elif ip.src < ip.dst:
        return "%s < %s" % (addrstring(ip.dst, p.dst), addrstring(ip.src, p.src))
    else:
        return "%s > %s" % (addrstring(ip.src, p.src), addrstring(ip.dst, p.dst))

def tsformat(ts):
    f, n= math.modf(ts)
    return time.strftime("%H:%M:%S", time.localtime(n))+("%.6f" % f)[1:]




class StreamAutoDetect:
    def __init__(self):
        self.data= {}
        self.decoder= None
    # todo for 'src' pass: 'clt', 'svr' + clt+svr addr:ports
    def handle(self, src, data, ofs, last):
        if self.decoder:
            return self.decoder.handle(src, data, ofs, last)
        if src in self.data:
            data = self.data[src] + data[ofs:last]
            ofs, last= 0, len(data)
        
        # try to determine what decoder to use
        for cls in decoders:
            # todo: pass both svr+clt traffic to isvaliddata.
            if cls.isvaliddata(data, ofs, last):
                if src in self.data:
                    del self.data[src]
                self.setdecoder(cls, src, data, ofs, last)
                return


    def setdecoder(self, cls, src, sdata, ofs, last):
        self.decoder= cls(self)

        # first forward older data
        for s, ddata in self.data.items():
            o= self.decoder.handle(s, ddata, 0, len(ddata))
            # todo: resulting ofs
            del self.data[s]
            if o<len(ddata):
                print("stream WARN: ddata remaining: %s" % (ddata[o:].encode("hex")))
        # then forward this data
        ofs= self.decoder.handle(src, sdata, ofs, last)

        # todo: optionally clear data
        #self.data[src]= sdata
        if ofs<last:
            print("stream WARN: sdata remaining: %s" % (sdata[ofs:].encode("hex")))

    def handlegap(self, src, size):
        pass
        #print("gap: %d" % size)

class StreamDecoder:
    def __init__(self):
        self.seq= {}
        self.cur= {}
        self.protocol = StreamAutoDetect()
        self.totalgap = 0
        self.seqmap= {}

    def __del__(self):
        if any(len(x) for x in self.seqmap.values()):
            #print("seq: ", self.seq)
            #print("cur: ", self.cur)
            #print("map: ", self.seqmap)
            pass

    @staticmethod
    def tcpflags(tcp):
        f= ""
        if tcp.URG: f+="U"
        if tcp.ACK: f+="A"
        if tcp.PSH: f+="P"
        if tcp.RST: f+="R"
        if tcp.SYN: f+="S"
        if tcp.FIN: f+="F"
        return f


    # handle without packet reordering
    # ... this is currently not used, see 'reorder'
    def handle(self, ctx):
        src= addrstring(getaddr(ctx, "src"))
        dst= addrstring(getaddr(ctx, "dst"))

        if not src in self.seq:
            self.seq[src]= ctx.tcp.seq
        if not dst in self.seq and ctx.tcp.ack:
            self.seq[dst]= ctx.tcp.ack
        f= self.tcpflags(ctx.tcp)

        skip= 0
        extra= ctx.tcp.FIN or ctx.tcp.SYN
        endseq= ctx.tcp.seq + len(ctx.tcp.payload)+extra

        if not src in self.cur:
            self.cur[src]= ctx.tcp.seq
        elif self.cur[src] < ctx.tcp.seq:
            #print("GAP: %08x-%08x" % (self.cur[src], ctx.tcp.seq))
            self.totalgap += ctx.tcp.seq-self.cur[src]

        elif self.cur[src] > ctx.tcp.seq:
            #print("OVERLAP: %08x-%08x" % (ctx.tcp.seq, self.cur[src]))
            # handle retransmit
            skip= self.cur[src] - ctx.tcp.seq

        if ctx.tcp.payload and self.totalgap:
            self.protocol.handlegap(src, self.totalgap)
            self.totalgap= 0

        #seqnr= "[%08x]" % ctx.tcp.seq-self.seq[src]
        seqnr= "[%08x-%08x:%08x]" % (ctx.tcp.seq, endseq, ctx.tcp.ack)
        print("%s TCP %-45s %s%-2s %s" % (tsformat(ctx.pcap.ts), pktprefix(ctx.ip, ctx.tcp), 
                    seqnr, f, ctx.tcp.payload.encode("hex")))

        if skip < len(ctx.tcp.payload):
            self.protocol.handle(src, ctx.tcp.payload, skip, len(ctx.tcp.payload))
        elif len(ctx.tcp.payload):
            print("dropped")
        self.cur[src] = endseq

    # handle with packet reordering
    def reorder(self, ctx):
        src= addrstring(getaddr(ctx, "src"))
        dst= addrstring(getaddr(ctx, "dst"))

#       if any(len(x) for x in self.seqmap.values()):
#           print(self.seqmap)

        # save all pkts in seqmap
        if not src in self.seqmap:
            self.seqmap[src]= {}
        self.seqmap[src][ctx.tcp.seq]= ctx

        # then try to process pkts
        for k in sorted(self.seqmap[src].keys()):
            ctx= self.seqmap[src][k]

            if not src in self.seq:
                self.seq[src]= ctx.tcp.seq
            if not dst in self.seq and ctx.tcp.ack:
                self.seq[dst]= ctx.tcp.ack
            f= self.tcpflags(ctx.tcp)

            skip= 0
            extra= ctx.tcp.FIN or ctx.tcp.SYN
            endseq= ctx.tcp.seq + len(ctx.tcp.payload)+extra

            if not src in self.cur:
                self.cur[src]= ctx.tcp.seq
            elif self.cur[src] < ctx.tcp.seq:
                # gap -> output later
                # todo: on FIN: do forward gapped data to protocol.handler.
                ##print("gap %d" % (ctx.tcp.seq-self.cur[src]))
                break
            elif self.cur[src] > ctx.tcp.seq:
                #print("OVERLAP: %08x-%08x" % (ctx.tcp.seq, self.cur[src]))
                # handle retransmit
                skip= self.cur[src] - ctx.tcp.seq

                ##print("retransmitted %d" % skip)

            # todo: detect server/client direction
            #   client: SYN has ctx.tcp.ack==0
            #   server: SYN has ctx.tcp.ack!=0


            #seqnr= "[%08x]" % ctx.tcp.seq-self.seq[src]
            seqnr= "[%08x-%08x %08x]" % (ctx.tcp.seq, endseq, ctx.tcp.ack)
            print("%s TCP %-45s %s%-2s" % (tsformat(ctx.pcap.ts), pktprefix(ctx.ip, ctx.tcp),
                        seqnr, f))

            if skip < len(ctx.tcp.payload):
                # todo: pass server/client flag + source/dest ports
                self.protocol.handle(src, ctx.tcp.payload, skip, len(ctx.tcp.payload))
            self.cur[src] = endseq

            del self.seqmap[src][k]



class StreamManager:
    def __init__(self):
        self.streams= {}
    def handle(self, ctx):
        tag= pkttag(ctx.ip, ctx.tcp)
        if not tag in self.streams:
            self.streams[tag]= StreamDecoder()
        self.streams[tag].reorder(ctx)


