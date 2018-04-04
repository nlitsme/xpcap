from udp_decoders.dhcp import DHCPPacket
from udp_decoders.dns import DNSPacket

# some code shared with the stream decoder
from stream import tsformat, pktprefix

# handle message based protocols

class PacketManager:
    def __init__(self):
        self.dns= DNSPacket
        self.dhcp = DHCPPacket()
    def handle(self, ctx):
        print("%s UDP %s  %s" % (tsformat(ctx.pcap.ts), pktprefix(ctx.ip, ctx.udp), ctx.udp.payload.encode("hex")))
        if {53,5353} & {ctx.udp.src, ctx.udp.dst}:
            r, o= self.dns.parse(ctx.udp.payload, 0, len(ctx.udp.payload))
            print("DNS:", r)
        elif {67,68} & {ctx.udp.src, ctx.udp.dst}:
            d, o= self.dhcp.parse(ctx.udp.payload, 0, len(ctx.udp.payload))
            print("DHCP:", d)


