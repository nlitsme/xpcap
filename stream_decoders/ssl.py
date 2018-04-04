import struct
import re

from stream_decoders import StreamDecoder

# decodes ssl handshakes


# reads  ssl.log + any privkeys
class SslKeymanager:
    def __init__(self):
        self.msbyrandom= {}
        self.prebypubkey= {}
        self.privbypub= {}

    def add(self, path):
        with open(path) as fh:
            data= fh.read()
            if self.isDER(data):
                self.processDER(data)
            elif self.isSSLLOG(data):
                self.processSSLLOG(data)
            elif self.isPEM(data):
                self.processPEM(data)


    @staticmethod
    def isSSLLOG(data):
        return re.match(r'(?:CLIENT_RANDOM|RSA) [0-9a-f]+ [0-9a-f]+', data)
    
    def processSSLLOG(self, data):
        for m in re.finditer(r'(\w+) ([0-9a-f]+) ([0-9a-f]+)', data):
            if m and m.group(1)=="CLIENT_RANDOM":
                clt= m.group(2).decode("hex")
                ms= m.group(3).decode("hex")
                self.msbyrandom[clt]= ms
            if m and m.group(1)=="RSA":
                pub= m.group(2).decode("hex")
                pre= m.group(3).decode("hex")
                self.prebypubkey[clt]= pre

    @staticmethod
    def isPEM(data):
        return re.search(r'-----BEGIN RSA PRIVATE KEY-----', data)
    def processPEM(data):
        for m in re.finditer(r'-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----', data, re.MULTILINE):
            self.processDER(b64decode(m.group(1)))


    # test if data is a DER encoded private key
    @staticmethod
    def isDER(data):
        # 00000000: 30 82 02 5c  02 01 00     02 81 81 00 cb ...          privkey
        # 00000000: 30 82 02 9c  30 82 02 05  a0 03 02 01 02  02 06  ...  cert
        # 00000000: 30 82 0e fe  02 01 03  30 82 0e b9  06 09 2a ...      pkcs12
        if data[0]!='0':
            return False
        if data[1]=="\x81":
            l1= ord(data[2])
            o= 3
        elif data[1]=="\x82":
            l1= ord(data[2])*256+ord(data[3])
            o= 4
        else:
            return False
        if data[o:o+3]=="\x02\x01\x00":
            return True
        if data[o:o+3]=="\x02\x01\x03":
            return True
        if data[o:o+3]=="\x06\x09\x2a":
            return True

        if data[o]!="0":
            return False
        if data[o+1]=="\x81":
            l2= ord(data[o+2])
            o += 3
        elif data[o+1]=="\x82":
            l2= ord(data[o+2])*256+ord(data[o+3])
            o += 4
        else:
            return False

        return 0x40 < l2-l1 < 0x1000

    # process private key in DER encoded format
    def processDER(self, data):
        a0, a1= der.get((0,), data, 0, len(data))
        n= der.iter(data, a0, a1)
        n.next()   # skip 00
        mod0, mod1= n.next()
        pubexp0, pubexp1= n.next()
        privexp0, privexp1= n.next()

        if mod0<mod1 and data[mod0]=="\x00":
            mod0 += 1
        if privexp0<privexp1 and data[privexp0]=="\x00":
            privexp0 += 1
        self.privbypub[data[mod0:mod0+8]]= data[privexp0:privexp1]


    # lookup private key given the public key
    def getprivkey(self, pubkey):
        if pubkey[:8] in self.privbypub:
            return self.privbypub[pubkey[:8]]

    # lookup the masterkey given the client random, or the public key
    def getmasterkey(self, cltrandom):
        # either by cltrandom, or by encrypted premaster ( RSA 8 bytes -> premaster )
        if cltrandom in self.msbyrandom:
            return self.msbyrandom[cltrandom]
        if cltrandom[:8] in self.prebypubkey:
            return self.prebypubkey[cltrandom[:8]]

keys= SslKeymanager()

class SSLDecryptor:
    def __init__(self, info):
        pass
    def decrypt(self, data):
        return ""

class SslDecoder:
    def __init__(self, ad):
        self.ad= ad
        self.outer= {
                0x14: self.HandleChangeCipher,
                0x15: self.HandleAlert,
                0x16: self.HandleHandshake,
                0x17: self.HandleCipherData,
                0x18: self.HandleHeartbeat,
        }
        self.handshake= {
                0x00: self.HandleHSHelloRequest,
                0x01: self.HandleHSClientHello,
                0x02: self.HandleHSServerHello,
                0x04: self.HandleHSNewSessionTicker,
                0x0b: self.HandleHSCertificate,
                0x0c: self.HandleHSServerKeyExchange,
                0x0d: self.HandleHSCertificateRequest,
                0x0e: self.HandleHSServerHelloDone,
                0x0f: self.HandleHSCertificateVerify,
                0x10: self.HandleHSClientKeyExchange,
                0x14: self.HandleHSFinished,
                0x15: self.HandleHSCertificateURL,
                0x16: self.HandleHSCertificateStatus,
        }
        self.odata= ""
        self.hdata= ""

        # client + server certs
        self.certs=[ [], [] ]
        self.kxdata=[ [], [] ]
        self.random=[ [], [] ]
        self.cc= [ [], [] ]

    @staticmethod
    def isvaliddata(data, ofs, last):
        if last-ofs<11: return
        f= struct.unpack_from("<BBBHBBHBB", data, ofs)
        if f[0]!=22: return
        if f[1]!=3: return
        if f[2]>3: return
        if f[4]==1:
            if f[6] > f[3]: return
            if f[7]!=3: return
            if f[8]>3: return
            return True

    def handle(self, src, data, ofs, last):
        if self.odata:
            data = self.odata + data[ofs:last]
            ofs, last= 0, len(data)

        # todo: determine 'frm'  from src
        frm= 0

        while True:
            o= self.ProcessOuterlayer(frm, data, ofs, last)
            if o==-1:
                break
            ofs= o

        if ofs<last:
            self.odata= data[ofs:last]
        else:
            self.odata= ""
        return last

    # splits stream in handshake, cipher, etc packets
    # return negative for error: -1 = needmore,  -2 = error
    # return positive: new offset
    def ProcessOuterlayer(self, frm, data, ofs, last):
        if ofs+5>last:
            return -1
        typ, version, pktlen= struct.unpack_from(">BHH", data, ofs)  ; ofs += 5
        if ofs+pktlen>last:
            return -1  # need more

        if typ in self.outer:
            if self.cc[frm]:
                decrypted= self.cc[frm].decrypt(data[ofs:ofs+pktlen])
                self.outer[typ](version, frm, decrypted, 0, len(decrypted))
            else:
                self.outer[typ](version, frm, data, ofs, ofs+pktlen)
        else:
            print("unknown ssl pkt type: %02x" % typ)
            print(data.encode("hex"))

        ofs += pktlen

        return ofs

    # handle handshake frame, splits into clienthello, serverhello, etc.
    def HandleHandshake(self, version, frm, data, ofs, last):
        if self.hdata:
            data = self.hdata + data[ofs:last]
            ofs, last= 0, len(data)

        while True:
            o= self.ProcessHandshake(frm, data, ofs, last)
            if o==-1:
                break
            ofs = o

        if ofs<last:
            self.hdata= data[ofs:last]
        else:
            self.hdata= ""

    # dispatches single handshake packet
    def ProcessHandshake(self, frm, data, ofs, last):
        # todo: decrypt after 'cc' packet received
        if ofs+4>last:
            return -1
        t, l2, l1, l0= struct.unpack_from("BBBB", data, ofs)  ; ofs += 4
        hslen= (l2<<16)|(l1<<8)|l0
        if ofs+hslen>last:
            return -1
        if t in self.handshake:
            self.handshake[t](frm, data, ofs, last)
        else:
            print("unknown ssl hs type: %02x" % t)
        ofs += hslen
        return ofs



    def HandleCipherData(self, version, frm, data, ofs, last):
        print("ssl cipher: %s" % data[ofs:last].encode("hex"))

    def HandleAlert(self, version, frm, data, ofs, last):
        print("ssl alert: %s" % data[ofs:last].encode("hex"))

    def HandleChangeCipher(self, version, frm, data, ofs, last):
        print("ssl cc: %s" % data[ofs:last].encode("hex"))

        self.cc[frm]= SSLDecryptor(self)

    def HandleHeartbeat(self, version, frm, data, ofs, last):
        print("ssl hb: %s" % data[ofs:last].encode("hex"))

    def HandleHSHelloRequest(self, frm, data, ofs, last):
        print("ssl hs:hloreq: %s" % data[ofs:last].encode("hex"))

    def HandleExtensions(self, data, ofs, last):
        extsize,= struct.unpack_from(">H", data, ofs)            ; ofs += 2
        if ofs+extsize>last:
            print("ssl extension too large")
        while ofs+4<=last:
            exttyp, extlen= struct.unpack_from(">HH", data, ofs) ; ofs += 4

            print("    %04x: %s" % (exttyp, data[ofs:ofs+extlen]))

            ofs += extlen

    def HandleHSClientHello(self, frm, data, ofs, last):
        clientver, clientrandom, sidlen= struct.unpack_from(">H32sB", data, ofs)
        ofs += 3+32
        sessionid= data[ofs:ofs+sidlen]                                 ; ofs += sidlen
        ciplen,= struct.unpack_from(">H", data, ofs)                    ; ofs += 2
        cipherlist= struct.unpack_from(">%dH" % (ciplen/2), data, ofs)  ; ofs += ciplen

        complen,= struct.unpack_from(">B", data, ofs)                   ; ofs += 1
        complist= struct.unpack_from(">%dB" % complen, data, ofs)       ; ofs += complen

        self.random[frm]= clientrandom
        print("ssl hs:ch: v%04x, rnd:%s, sid:%s" % (clientver, clientrandom.encode("hex"), sessionid.encode("hex")))
        print("    ciphers: %s" % (",".join(map(lambda x:"%04x" % x, cipherlist))))
        print("    comp: %s" % (",".join(map(lambda x:"%04x" % x, complist))))

        if ofs<last:
            self.HandleExtensions(data, ofs, last)

    def HandleHSServerHello(self, frm, data, ofs, last):
        serverver, serverrandom, sidlen= struct.unpack_from(">H32sB", data, ofs)
        ofs += 3+32
        sessionid= data[ofs:ofs+sidlen]                     ; ofs += sidlen
        cipher, comp= struct.unpack_from(">HB", data, ofs)  ; ofs += 3

        self.random[frm]= serverrandom
        self.cipher= cipher
        print("ssl hs:sh: v%04x, rnd:%s, sid:%s" % (serverver, serverrandom.encode("hex"), sessionid.encode("hex")))
        print("   using cipher %04x, comp %04x" % (cipher, comp))

        if ofs<last:
            self.HandleExtensions(data, ofs, last)


    def HandleHSNewSessionTicker(self, frm, data, ofs, last):
        print("ssl hs:ns: %s" % data[ofs:last].encode("hex"))

    def HandleHSCertificate(self, frm, data, ofs, last):
        def getnum24(data, ofs):
            l2, l1, l0= struct.unpack_from("BBB", data, ofs)
            return (l2<<16) | (l1<<8) | l0

        print("ssl hs:cert: %s" % data[ofs:last].encode("hex"))
        total= getnum24(data, ofs)       ; ofs += 3
        endofs= ofs + total
        while ofs < endofs:
            certlen= getnum24(data, ofs) ; ofs += 3
            self.certs[frm].append(data[ofs:ofs+certlen]) ; ofs += certlen

    def HandleHSServerKeyExchange(self, frm, data, ofs, last):
        print("ssl hs:svrkx: %s" % data[ofs:last].encode("hex"))
        kxlen, = struct.unpack_from(">H", data, ofs)  ; ofs += 2
        self.kxdata[frm]= data[ofs:ofs+kxlen]

    def HandleHSCertificateRequest(self, frm, data, ofs, last):
        print("ssl hs:certreq: %s" % data[ofs:last].encode("hex"))

    def HandleHSServerHelloDone(self, frm, data, ofs, last):
        print("ssl hs:svrhdone: %s" % data[ofs:last].encode("hex"))

    def HandleHSCertificateVerify(self, frm, data, ofs, last):
        print("ssl hs:certvfy: %s" % data[ofs:last].encode("hex"))

    def HandleHSClientKeyExchange(self, frm, data, ofs, last):
        print("ssl hs:cltkx: %s" % data[ofs:last].encode("hex"))
        kxlen, = struct.unpack_from(">H", data, ofs)  ; ofs += 2
        self.kxdata[frm]= data[ofs:ofs+kxlen]

    def HandleHSFinished(self, frm, data, ofs, last):
        print("ssl hs:finished: %s" % data[ofs:last].encode("hex"))

    def HandleHSCertificateURL(self, frm, data, ofs, last):
        print("ssl url:???: %s" % data[ofs:last].encode("hex"))

    def HandleHSCertificateStatus(self, frm, data, ofs, last):
        print("ssl certstat:???: %s" % data[ofs:last].encode("hex"))


toplevel=SslDecoder
