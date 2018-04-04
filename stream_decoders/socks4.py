import struct

from stream_decoders import StreamDecoder

# decode socks4 connections

class Socks4Decoder(StreamDecoder):
    def __init__(self, ad):
        StreamDecoder.__init__(self, ad)
        self.state= 0
        self.data= ["", ""]
    @staticmethod
    def isvaliddata(data, ofs, last):
        # 04 {01,02,f0,f1}
        if ofs+2>last:
            return False
        v, r= struct.unpack_from("BB", data, ofs)
        return v==4 and r in (1,2,0xf0, 0xf1)

    def handle(self, src, data, ofs, last):
        if not src in self.peers:
            self.peers[src]= len(self.peers)
        dir = self.peers[src]
        if dir in self.data and self.data[dir]:
            data = self.data[dir] + data[ofs:last]
            ofs, last= 0, len(data)

        if self.state==0:  # await client method req
            if last-ofs<9:
                return
            v, req, port, addr, ulen= struct.unpack_from(">BBHLB", data, ofs) ; ofs += 9
            if ofs+ulen>=last:
                return

            uname= data[ofs:ofs+ulen]      ; ofs += ulen
            if addr=="\x00\x00\x00\x01":
                ix= data.find("\x00", ofs)
                if ix<0:
                    return
                dstname= data[ofs:ofs+ix]  ; ofs += ix+1
            else:
                dstname= ""

            state = 1  # await server response
            self.data[dir]= data[ofs:last]
            print("socks4 req: %02x %08x.%04x (%s) (%s)" % (req, addr, port, uname, dstname))
            if last>ofs:
                print("-> %d bytes" % (last-ofs))
        elif self.state==1:
            if last-ofs<8:
                return

            v, res, port, addr= struct.unpack_from(">BBHL", data, ofs)  ; ofs += 8

            self.data[dir]= data[ofs:last]

            print("socks4 ans: %02x %08x.%04x" % (res, addr, port))
            if last>ofs:
                print("-> %d bytes" % (last-ofs))
        else:
            pass

        return last


toplevel=Socks4Decoder

