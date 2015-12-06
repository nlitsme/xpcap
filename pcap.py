import struct
#https://wiki.wireshark.org/Development/LibpcapFileFormat

# this class creates a generator for enumerating pcap file contents.
class pcap:
    def __init__(self, fh):
        self.fh= fh
        hdr= self.fh.read(24)
        magic,= struct.unpack_from("<L", hdr, 0)
        if magic==0xd4c3b2a1 or magic==0x4d3cb2a1:
            self.endianness= ">"
        elif magic==0xa1b2c3d4 or magic==0xa1b23c4d:
            self.endianness= "<"
        else:
            raise Exception("invalid pcap magic %08x" % magic)

        if magic==0xa1b23c4d or magic==0x4d3cb2a1:
            self.fraction_scale = 1000000000.0
        elif magic==0xa1b2c3d4 or magic==0xd4c3b2a1:
            self.fraction_scale = 1000000.0

        vmaj, vmin, zone, figs, snaplen, linktype= struct.unpack_from(self.endianness + "HHLLLL", hdr, 4)

        self.linktype= linktype
    def __iter__(self):
        return self

    def next(self):
        hdr= self.fh.read(16)
        if len(hdr)<16:
            raise StopIteration 
        seconds, fraction, caplen, wirelen= struct.unpack(self.endianness+"LLLL", hdr)

        return seconds+fraction/self.fraction_scale, self.fh.read(caplen)


