from __future__ import print_function
import argparse
import pcap
import struct
import math
import os.path

import stream
import messages
import stream_decoders.ssl

from bitfields import bitfields 

class empty: pass


class PacketDecoder:
    def __init__(self):
        self.ip= {
# http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
                1:self.parse_icmp,
                # 2: igmp
                6:self.parse_tcp,
                17:self.parse_udp,
                # 50: Encapsulated Security Payload ( IPSEC )
        }
        self.ether= {
# http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
                0x0800:self.parse_ipv4,
                0x0806:self.parse_arp,
                0x86dd:self.parse_ipv6,
# 0x8100 - Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag)
# 0x888e - 802.1x port based network access control
# 0x88cc - 802.1AB - Link Layer Discovery Protocol (LLDP)
# 0x890d - 802.11 - Fast Roaming Remote Request (802.11r)
# 0x9123
        }
        self.pcap= {
# http://www.tcpdump.org/linktypes.html
                127:self.parse_radio,
                0:self.parse_loopback,
                1:self.parse_ether,
                101:self.parse_ipv4,
                249:self.parse_usb,
#   0  LINKTYPE_NULL  ( loopback )
#   6  LINKTYPE_IEEE802_5
#   9  LINKTYPE_PPP
#  10  LINKTYPE_FDDI
# 101  LINKTYPE_RAW
# 104  LINKTYPE_C_HDLC
# 107  LINKTYPE_FRELAY
# 113  LINKTYPE_LINUX_SLL
# 235  LINKTYPE_DVB_CI
# 249  LINKTYPE_USBPCAP
        }
        self.parse_wlan= True

    def parse_pcap(self, ctx, pkt, ofs, last):
        if ctx.pcap.linktype in self.pcap:
            self.pcap[ctx.pcap.linktype](ctx, pkt, ofs, last)
        else:
            print("unknown linktype %d" % ctx.pcap.linktype)
            print(pkt.encode("hex"))

    # pcap 2.4 z0 0x0 0xffff lt127[DLT_IEEE802_11_RADIO]
    # http://www.radiotap.org/
    # capture using:
    #    tcpdump -n -i en0 -I -y IEEE802_11_RADIO -B 300000 -w radio.pcap
    def parse_radio(self, ctx, pkt, ofs, last):
        def getoptional(bit, align, fmt, pkt, ofs, last):
            if not bit:
                return None, ofs
            if ofs & ((1<<align)-1):
                ofs = ((ofs-1)|((1<<align)-1))+1
            endofs= ofs+struct.calcsize(fmt)
            if endofs>last:
                raise Exception("radiotap optional too large")
            val, = struct.unpack_from(fmt, pkt, ofs)
            return val, endofs

        ctx.radio= rd= empty()
        rd.version, rd.hlen, rd.pflags = struct.unpack_from("<BxHL", pkt, ofs)

        hdrend= ofs+rd.hlen
        if hdrend>last:
            raise Exception("radiotap hdr too large")
        ofs += 8

        rd.tsft,      ofs= getoptional(rd.pflags&(1<<0), 8, "<Q", pkt, ofs, hdrend)
        rd.flags,     ofs= getoptional(rd.pflags&(1<<1), 1, "<B", pkt, ofs, hdrend) #  1=during CFP, 2= short preamble, 4=WEP, 8=frag, 10=FCS, 20=padded, 40=fcsfailed
        rd.rate,      ofs= getoptional(rd.pflags&(1<<2), 1, "<B", pkt, ofs, hdrend)
        rd.channel,   ofs= getoptional(rd.pflags&(1<<3), 2, "<L", pkt, ofs, hdrend) # freq + flags
        rd.hopping,   ofs= getoptional(rd.pflags&(1<<4), 2, "<H", pkt, ofs, hdrend) # FHSS
        rd.signal,    ofs= getoptional(rd.pflags&(1<<5), 1, "<B", pkt, ofs, hdrend) # dbm_antsignal
        rd.noise,     ofs= getoptional(rd.pflags&(1<<6), 1, "<B", pkt, ofs, hdrend) # dbm_antnoise
        rd.lockqual,  ofs= getoptional(rd.pflags&(1<<7), 2, "<H", pkt, ofs, hdrend) # lock quality
        rd.attenuat,  ofs= getoptional(rd.pflags&(1<<8), 2, "<H", pkt, ofs, hdrend) # tx attenuation
        rd.txattenuat,ofs= getoptional(rd.pflags&(1<<9), 2, "<H", pkt, ofs, hdrend) # db tx attenuation
        rd.txpower,   ofs= getoptional(rd.pflags&(1<<10), 1, "<b", pkt, ofs, hdrend) # dbm tx power
        rd.antenna,   ofs= getoptional(rd.pflags&(1<<11), 1, "<B", pkt, ofs, hdrend)
        rd.antsignal, ofs= getoptional(rd.pflags&(1<<12), 1, "<B", pkt, ofs, hdrend) # db_antsignal
        rd.antnoise,  ofs= getoptional(rd.pflags&(1<<13), 1, "<B", pkt, ofs, hdrend) # db_antnoise
        rd.rxflags,   ofs= getoptional(rd.pflags&(1<<14), 2, "<H", pkt, ofs, hdrend)
        rd.txflags,   ofs= getoptional(rd.pflags&(1<<15), 2, "<H", pkt, ofs, hdrend)
        rd.rts_retries,ofs= getoptional(rd.pflags&(1<<16), 1, "<B", pkt, ofs, hdrend)
        rd.dat_retries,ofs= getoptional(rd.pflags&(1<<17), 1, "<B", pkt, ofs, hdrend)
        rd.xchannel,  ofs= getoptional(rd.pflags&(1<<18), 4, "<Q", pkt, ofs, hdrend)
        rd.mcs,       ofs= getoptional(rd.pflags&(1<<19), 1, "<3s", pkt, ofs, hdrend)
        rd.ampdu,     ofs= getoptional(rd.pflags&(1<<20), 4, "<Q", pkt, ofs, hdrend)
        rd.vht,       ofs= getoptional(rd.pflags&(1<<21), 2, "<12s", pkt, ofs, hdrend)
        rd.timestamp, ofs= getoptional(rd.pflags&(1<<22), 8, "<12s", pkt, ofs, hdrend)


        # skip encrypted + badfcs packets
        if rd.flags&0x44:
            return
        self.parse_80211(ctx, pkt, hdrend, last)

    def parse_80211(self, ctx, pkt, ofs, last):
        # type
        FCTYPE_MGMT=0
        FCTYPE_CTRL=1
        FCTYPE_DATA=2

        # CTRL subtypes
        CTRL_CTS=0xc,
        CTRL_ACK=0xd,
        CTRL_BLOCKACKREQUEST=0x8,
        CTRL_BLOCKACK=0x9,

        # data subtype bits
        FCDATA_QOS= 8
        FCDATA_NODATA= 4

        def have_a2(wifi):
            if wifi.type in (FCTYPE_DATA, FCTYPE_MGMT):
                return True
            if wifi.type != FCTYPE_CTRL:
                return False
            return wifi.subtype not in (CTRL_CTS, CTRL_ACK)
        def have_a3(wifi):
            if wifi.type in (FCTYPE_DATA, FCTYPE_MGMT):
                return True
        def have_seqctl(wifi):
            if wifi.type in (FCTYPE_DATA, FCTYPE_MGMT):
                return True
            if wifi.type != FCTYPE_CTRL:
                return False
            return wifi.subtype in (CTRL_BLOCKACKREQUEST, CTRL_BLOCKACK)
        def have_a4(wifi):
            return wifi.type == FCTYPE_DATA and wifi.toDS and wifi.fromDS
        def have_qos(wifi):
            return wifi.type == FCTYPE_DATA and (wifi.subtype&FCDATA_QOS)

        wifi= ctx.wifi= empty()

        fctl, associd= struct.unpack_from("<HH", pkt, ofs)
        ofs += 4
        wifi.Order, wifi.WEP, wifi.moreData, wifi.pwrMgmt, wifi.retry, wifi.moreFrag, wifi.fromDS, wifi.toDS, \
            wifi.subtype, wifi.type, wifi.proto = bitfields(fctl, 1,1,1,1, 1,1,1,1, 4,2,2)

        a1= pkt[ofs:ofs+6]       ; ofs += 6
        if have_a2(wifi):
            a2= pkt[ofs:ofs+6]   ; ofs += 6
        if have_a3(wifi):
            a3= pkt[ofs:ofs+6]   ; ofs += 6
        if have_seqctl(wifi):
            if ofs>=last:  # workaround
                return
            seqctl,= struct.unpack_from("<H", pkt, ofs) ; ofs += 2
        if have_a4(wifi):
            a4= pkt[ofs:ofs+6]   ; ofs += 6
        if have_qos(wifi):
            qos,= struct.unpack_from("<H", pkt, ofs)    ; ofs += 2

        # data
        if wifi.type==FCTYPE_DATA and not (wifi.subtype&FCDATA_NODATA):
            if not wifi.WEP:
                self.parse_llc(ctx, pkt, ofs, last)
        elif not self.parse_wlan:
            pass
        elif wifi.type==FCTYPE_MGMT:
            print("wlan mgmt: %s." % pkt[ofs:last].encode("hex"))
        elif wifi.type==FCTYPE_CTRL and wifi.subtype==CTRL_BLOCKACK:
            print("wlan ctrl: %s." % pkt[ofs:last].encode("hex"))
        else:
            print("wlan ????: %s." % pkt[ofs:last].encode("hex"))

    def parse_llc(self, ctx, pkt, ofs, last):
        if pkt[ofs:ofs+2] != "\xaa\xaa":
            print("unknown LLC header: %s" % pkt.encode("hex"))
            return
        llc = ctx.llc= empty()
        llc.dsap, llc.ssap, llc.ctrl, llc.org, llc.typ= struct.unpack_from(">BBB3sH", pkt, ofs)
        ofs += 8
        if llc.typ<0x600:
            print("unknown ether packet, len=%04x" % llc.typ)
            print(pkt.encode("hex"))
        elif llc.typ in self.ether:
            self.ether[llc.typ](ctx, pkt, ofs, last)
        else:
            print("unknown llc proto: %04x" % llc.typ)
            print(pkt.encode("hex"))


    # this format is created by capturing lo0, or tun0
    def parse_loopback(self, ctx, pkt, ofs, last):
        ctx.loopback= empty()
# address family from socket.h
        af_le,= struct.unpack_from("<L", pkt, ofs)
        af_be,= struct.unpack_from(">L", pkt, ofs)
        ctx.loopback.af = af_le if af_le < af_be else af_be
        ofs += 4
        if ctx.loopback.af==2:
            self.parse_ipv4(ctx, pkt, ofs, last)
        elif ctx.loopback.af==30:
            self.parse_ipv6(ctx, pkt, ofs, last)
        else:
            print("unknown loopback af: %d" % ctx.loopback.af)

    # pcap 2.4 z0 0x0 0xffff lt1[DLT_EN10MB]
    def parse_ether(self, ctx, pkt, ofs, last):
        ctx.eth = eth= empty()
        eth.dst, eth.src, eth.typ= struct.unpack_from(">6s6sH", pkt, ofs)
        ofs += 14
        if ofs>last:
            raise Exception("ether pkt too short")
        if eth.typ<0x600:
            print("unknown ether packet, len=%04x" % eth.typ)
            print(pkt.encode("hex"))
        elif eth.typ in self.ether:
            self.ether[eth.typ](ctx, pkt, ofs, last)
        else:
            print("unknown ether proto: %04x" % eth.typ)
            print(pkt.encode("hex"))

    def parse_ipv4_options(self, ctx, pkt, ofs, last):
        # 1bit:copied, 
        # 2bit:class:   control, reserved, measurement, reserved 
        # 5bit:number, 

        ctx.ip.options= pkt[ofs:last]
        #todo

    def parse_usb(self, ctx, pkt, ofs, last):
        pass
    # hlen, irp, status, func = struct.unpack_from("<HQLH", pkt, ofs)

    def parse_ipv4(self, ctx, pkt, ofs, last):
        ctx.ip = ip = empty()
        verhlen, ip.tos, ip.length, ip.ident, ip.frag, ip.ttl, ip.proto, ip.check, ip.src, ip.dst= struct.unpack_from(">BBHHHBBH4s4s", pkt, ofs)

        ip.version= verhlen>>4
        ip.hlen= verhlen&15

        hdrendofs = ofs + ip.hlen*4
        if ip.version!=4:
            raise Exception("not ipv4")
        if ip.hlen<5:
            raise Exception("SHORT ip header: verhlen=%02x" % verhlen)
        if hdrendofs > last:
            raise Exception("ip header too large")

        if ip.hlen>5:
            self.parse_ipv4_options(ctx, pkt, ofs+20, hdrendofs)

        if ip.proto in self.ip:
            self.ip[ip.proto](ctx, pkt, hdrendofs, last)
        else:
            print("unknown ip proto:", ip.proto)
            print(pkt.encode("hex"))

    def parse_arp(self, ctx, pkt, ofs, last):
        ctx.arp= pkt[ofs:last]
        #todo
    def parse_ipv6(self, ctx, pkt, ofs, last):
        ip= ctx.ipv6= empty()
        #todo
        ip.proto= -1

    def parse_icmp(self, ctx, pkt, ofs, last):
        ctx.icmp= icmp= empty()
        icmp.typ, icmp.code, icmp.check, icmp.ident, icmp.seq= struct.unpack_from(">BBHHH", pkt, ofs)
        ofs += 8
        ctx.icmp.payload= pkt[ofs:last]
        #todo

    def parse_tcp_options(self, ctx, pkt, ofs, last):
        ctx.tcp.options= pkt[ofs:last]
        #todo

    def parse_tcp(self, ctx, pkt, ofs, last):
        ctx.tcp= tcp= empty()
        tcp.src, tcp.dst, tcp.seq, tcp.ack, hlen, tcp.flags, tcp.window, tcp.check, tcp.urgent = struct.unpack_from(">HHLLBBHHH", pkt, ofs)
        tcp.hlen = hlen>>4

        tcp.URG, tcp.ACK, tcp.PSH, tcp.RST, tcp.SYN, tcp.FIN= bitfields(tcp.flags, 1, 1, 1, 1, 1, 1)
# PSH: sender has emptied its buffers ( usually last of burst of packets )

        hdrendofs= ofs+tcp.hlen*4

        if tcp.hlen<5:
            raise Exception("SHORT tcp header: hlen=%02x" % hlen)
        if hdrendofs > last:
            raise Exception("tcp header too large")

        if tcp.hlen>5:
            self.parse_tcp_options(ctx, pkt, ofs+0x14, hdrendofs)

        ctx.tcp.payload= pkt[hdrendofs:last]
        #todo

    def parse_udp(self, ctx, pkt, ofs, last):
        ctx.udp= udp= empty()
        udp.src, udp.dst, udp.len, udp.check= struct.unpack_from(">HHHH", pkt, ofs)
        ofs += 8
        ctx.udp.payload= pkt[ofs:last]
        #todo

class CollectStatistics:

    # class for calculating average + deviation
    class Stat:
        def __init__(self):
            self.sum= 0
            self.sum2= 0
            self.nr= 0
        def add(self, value):
            self.nr += 1
            self.sum += value
            self.sum2 += value*value
        def total(self):
            return self.sum
        def average(self):
            return self.sum/self.nr
        def total(self):
            return self.sum
        def deviation(self):
            return math.sqrt(self.nr*self.sum2-self.sum**2)/self.nr

    def __init__(self):
        self.stats= {}
        self.nr= {}
    def count(self, tag):
        if not tag in self.nr:
            self.nr[tag]= 0
        self.nr[tag] += 1
    def add(self, tag, value):
        if not tag in self.stats:
            self.stats[tag]= CollectStatistics.Stat()
        self.stats[tag].add(value)
    def dump(self):
        for t,s in self.nr.items():
            print("%8d %s" % (s, t))
        for t,s in self.stats.items():
            print("%8.1f %8.1f %8.0f %s" % (s.average(), s.deviation(), s.total(), t))

decoder= PacketDecoder()

parser = argparse.ArgumentParser(description='Tool for quick analysis of tcp streams')
parser.add_argument('-p', '--port', type=int)
parser.add_argument('-l', '--ssllog', type=str)
parser.add_argument('-W', '--nowlan', action='store_true')
parser.add_argument('files',  nargs='*', type=str)

args = parser.parse_args()

stats= CollectStatistics()

if args.ssllog:
    ssl.keys.add(ssllog)

if args.nowlan:
    decoder.parse_wlan= False

for fn in args.files:
    if not os.path.isfile(fn):
        continue

    with open(fn) as fh:
        tcp= stream.StreamManager()
        udp= messages.PacketManager()
        try:
            packets= pcap.pcap(fh)
            print("==> %s <==" % fn)
        except:
            print("xpcap: %s Not a PCAP file" % fn)
            continue
        if not packets.linktype in decoder.pcap:
            print("unknown linktype: %d" % packets.linktype)
            try :
                ts, pkt = packets.next()
                print(pkt.encode("hex"))
                continue
            except:
                pass

        for ts, pkt in packets:
            ctx= empty()
            ctx.pcap= empty()
            ctx.pcap.ts= ts
            ctx.pcap.linktype= packets.linktype
            try:
                decoder.parse_pcap(ctx, pkt, 0, len(pkt))
                if hasattr(ctx, "tcp"):
                    stats.count("tcp.port.%d" % ctx.tcp.src)
                    stats.count("tcp.port.%d" % ctx.tcp.dst)
                    stats.add("tcp.bytes.%d" % ctx.tcp.src, len(ctx.tcp.payload))
                    stats.add("tcp.bytes.%d" % ctx.tcp.dst, len(ctx.tcp.payload))
                    if args.port is None or args.port in (ctx.tcp.src, ctx.tcp.dst):
                        tcp.handle(ctx)
                elif hasattr(ctx, "udp"):
                    stats.count("udp.port.%d" % ctx.udp.src)
                    stats.count("udp.port.%d" % ctx.udp.dst)
                    stats.add("udp.bytes.%d" % ctx.udp.src, len(ctx.udp.payload))
                    stats.add("udp.bytes.%d" % ctx.udp.dst, len(ctx.udp.payload))
                    if args.port is None or args.port in (ctx.udp.src, ctx.udp.dst):
                        udp.handle(ctx)
                elif hasattr(ctx, "ip"):
                    stats.count("ip.proto.%d" % ctx.ip.proto)
                elif hasattr(ctx, "ipv6"):
                    stats.count("ipv6.proto.%d" % ctx.ipv6.proto)
                elif hasattr(ctx, "eth"):
                    stats.count("eth.typ.%04x" % ctx.eth.typ)
                elif hasattr(ctx, "llc"):
                    stats.count("llc.typ.%04x" % ctx.llc.typ)
                else:
                    #print "WHAT??  %s" % ",".join(dir(ctx))
                    pass
            except Exception as e:
                print("E: %s" % e)
                print(pkt.encode("hex"))
                #raise

stats.dump()
