import struct

from stream_decoders import StreamDecoder

# decode socks5 connections

class Socks5Decoder(StreamDecoder):
    def __init__(self, ad):
        StreamDecoder.__init__(self, ad)
        self.state= 0
        self.data= ["", ""]
    @staticmethod
    def isvaliddata(data, ofs, last):
        # client: 050100  or 050102
        # server: 0500  or 0502
        if ofs+3>last:
            return False
        v, n, x= struct.unpack_from("BBB", data, ofs)
        if v!=5:
            return False
        if n==0 or n>4:
            return False
        if x>4:
            return False
        return True

    def handle(self, src, data, ofs, last):
        if not src in self.peers:
            self.peers[src]= len(self.peers)
        dir = self.peers[src]
        if dir in self.data and self.data[dir]:
            data = self.data[dir] + data[ofs:last]
            ofs, last= 0, len(data)

        if self.state==0:  # await client method req
            if last-ofs<3:
                return
            v, nr= struct.unpack_from("BB", data, ofs)   ; ofs += 2
            if ofs+nr>last:
                return
            methods= data[ofs:ofs+nr]                    ; ofs += nr

            print("socks5 client methods: %s" % methods.encode("hex"))
            self.state= 1
        elif self.state==1:  # await server method ack
            v, mth= struct.unpack_from("BB", data, ofs)  ; ofs += 2
            print("socks5: method = %d" % mth)
            if mth==2:
                self.state= 2
            elif mth==0:
                self.state= 4
            else:
                print("unsupported socks method")
        elif self.state==2:  # await username/password from client
            if last-ofs<3:
                return
            v, ulen= struct.unpack_from("BB", data, ofs) ; ofs += 2
            if ofs+ulen+1>last:
                return
            username= data[ofs:ofs+ulen]                 ; ofs += ulen
            plen= ord(data[ofs])                         ; ofs += 1
            if ofs+plen>last:
                return
            password= data[ofs:ofs+plen]                 ; ofs += plen

            print("socks5: login(%s/%s)" % (username, password))
            self.state= 3
        elif self.state==3: # wait server auth ack
            if last-ofs<2:
                return
            v, ok= struct.unpack_from("BB", data, ofs)   ; ofs += 2
            print("socks5: auth: %02x" % ok)
            self.state= 4
        elif self.state in (4,5): # wait client request
            if self.state==5 and dir==0:
                return
            if last-ofs<8:
                print("need 8 bytes hdr")
                return
            v, req, unk, atype= struct.unpack_from("BBBB", data, ofs)  ; ofs += 4

            address= None
            if atype==1:
                if ofs+4>last:
                    print("need 4 bytes")
                    return
                address,= struct.unpack_from("<L", data, ofs)       ; ofs += 4
            elif atype==4:
                if ofs+16>last:
                    print("need 16 bytes")
                    return
                address= struct.unpack_from("<HHHHHHHH", data, ofs) ; ofs += 16
            elif atype==3:
                alen= ord(data[ofs])                   ; ofs += 1
                if ofs+alen>last:
                    print("need %d bytes" % alen)
                    return
                address= data[ofs:ofs+alen]            ; ofs += alen
            else:
                print("socks: unknown address type: %d" % atype)
            port,= struct.unpack_from("<H", data, ofs) ; ofs += 2

            print("socks5 req: %02x %s.%04x" % (req, address, port))

            self.state += 1
        elif self.state==6:
            # todo: connect to new autodetect
            pass
        
        self.data[dir]= data[ofs:last]

        return last

toplevel=Socks5Decoder
