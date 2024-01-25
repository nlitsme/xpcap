#!/usr/bin/python3
import datetime
import struct
import sys
if sys.version_info[0] == 2:
    def xx(b):
        return "%02x" % ord(b)
    def escape(txt):
        for k, v in [ ("\n", "\\n"), ("\\", "\\\\") ]:
            txt = txt.replace(k, v)
        return txt
else:
    def xx(b):
        return "%02x" % (b)
    TRANSTABLE = str.maketrans({"'":"\\'", "\n":"\\n"})
    def escape(txt):
        return str.translate(txt, TRANSTABLE)

def hexdump(data):
    try:
        if data.startswith(b'<?xml') and data.endswith(b'>'):
            return escape(data.decode('utf-8'))
    except:
        pass
    if len(data)<=1024:
        return " ".join(xx(_) for _ in data)
    else:
        return hexdump(data[:256]) + " ... " + hexdump(data[-256:])

# pcap_usb_header
#  u_int64_t id;             00   // The 'id' field is used to link a 'submit' event with its coupled 'completion' or 'error' event.
#  u_int8_t event_type;      08   // The 'event_type' can be one of 'S', 'C' or 'E', to specify respectively, a 'submit', a 'completion' or an 'error' event.
#  u_int8_t transfer_type;   09   // The 'transfer_type' specifies if this transfer is isochronous (0), interrupt (1), control (2) or bulk (3).
#  u_int8_t endpoint_number; 0a   // The 'endpoint_number' also specifies the transfer direction: if the bit 0x80 is set, the direction is input (from the device to the host), otherwise it is output (from the host to the device).
#  u_int8_t device_address;  0b
#  u_int16_t bus_id;         0c
#  char setup_flag;          0e   // If the 'setup_flag' is 0, than the setup data is valid.
#  char data_flag;           0f   // If the 'data_flag' is 0, then this header is followed by the data with the associated URB. In an error event, the 'status' field specifies the error code.
#  int64_t ts_sec;           10
#  int32_t ts_usec;          18
#  int32_t status;           1c
#  u_int32_t urb_len;        20
#  u_int32_t data_len;       24
#  pcap_usb_setup setup;     28  union: either setup pkt, or  errcount+numdesc
#  int interval              30
#  int start_frame           34
#  unsigned xfer_flags       38
#  unsigned ndesc            3c
 


def usbdump(data):
    et, tt, ep = data[8:11]
    if chr(et)=='S':
        return f"{chr(et)}:{tt}:{ep:02x}  {data[40:48].hex()} {data[40+24:].hex()}"
    else:
        return f"{chr(et)}:{tt}:{ep:02x}   {data[40+24:].hex()}"

def roundup(a, b):
    return ((a-1)|(b-1)) + 1

class EnhancedPacket:
    """
000000e0:                         06 00 00 00 60 00 00 00
000000f0: 00 00 00 00 80 82 05 00 98 b3 04 d0 40 00 00 00

00000100: 40 00 00 00 80 5a e0 bd 5a a0 ff ff 53 03 83 07
00000110: 02 00 2d 3c 00 51 70 5c 00 00 00 00 98 73 0e 00
00000120: 8d ff ff ff 18 00 00 00 00 00 00 00 00 00 00 00
00000130: 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00
00000140: 00 00 00 00 60 00 00 00

    """
    def __init__(self, data):
        self.ifid, timeh, timel, self.caplen, self.wirelen  \
                = struct.unpack("<5L", data[:20])
        t = ((timeh<<32)|timel)
        self.time = datetime.datetime.fromtimestamp(t/1000000)

        o = 20
        self.data = data[o:o+self.caplen]
        o += roundup(self.caplen, 4)

        self.options = list(self.decodeoptions(data[o:]))

    def decodeoptions(self, data):
        o = 0
        while o < len(data):
            optcode, optlen, = struct.unpack_from("<HH", data, o)
            o += 4
            optdata = data[o:o+optlen]
            o += roundup(optlen, 4)
            if optcode==0:
                break
            elif optcode==123132:
                yield None
            else:
                print("unknown option", optcode)

    def optstr(self):
        if not self.options:
            return ""
        return "\n" + "\n".join(repr(_) for _ in self.options)

    def printusb(self):
        print("if%d, %s -- %s%s" % (self.ifid, self.time, usbdump(self.data), self.optstr()))

    def __repr__(self):
        return "if%d, t=%s -- %s%s" % (self.ifid, self.time, hexdump(self.data), self.optstr())


class IfNameOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "IFNAME:'%s'" % escape(self.txt)
class IfDescOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "IFDESC:'%s'" % escape(self.txt)
class IPv4Option:
    def __init__(self, data):
        self.ip, self.mask = struct.unpack("<LL", data)
    def __repr__(self):
        return "IPV4:%08x/%08x" % (self.ip, self.mask)
class TimeResolutionOption:
    def __init__(self, data):
        self.res = struct.unpack("B", data)
    def __repr__(self):
        return "TRES:%d" % self.res


class InterfaceDesc:
    """
00000090:                                     01 00 00 00
000000a0: 4c 00 00 00 dc 00 00 00 00 00 04 00

000000ac: 02 00 07 00 75 73 62 6d 6f 6e 30 00              usbmon0

000000b8: 09 00 01 00 06 00 00 00  

000000c0: 0c 00 19 00 4c 69 6e 75 78 20 34 2e 32 30 2e 36  ....Linux 4.20.6
000000d0: 2d 61 72 63 68 31 2d 31 2d 41 52 43 48 00 00 00  -arch1-1-ARCH...

000000e0: 00 00 00 00

000000e4: 4c 00 00 00

    """
    def __init__(self, data):
        self.linktype, self.reserved, self.snaplen = struct.unpack("<HHL", data[:8])
        o = 8
        self.options = list( self.decodeoptions(data[o:]) )

    def decodeoptions(self, data):
        o = 0
        while o < len(data):
            optcode, optlen, = struct.unpack_from("<HH", data, o)
            o += 4
            optdata = data[o:o+optlen]
            o += roundup(optlen, 4)
            if optcode==0:
                break
            elif optcode==1:
                yield CommentOption(optdata)
            elif optcode==2:
                yield IfNameOption(optdata)
            elif optcode==3:
                yield IfDescOption(optdata)
            elif optcode==4:
                yield IPv4Option(optdata)
            elif optcode==9:
                yield TimeResolutionOption(optdata)
            elif optcode==12:
                yield OSOption(optdata)
            else:
                print("unknown option", optcode)

    def optstr(self):
        if not self.options:
            return ""
        return "\n" + "\n".join(repr(_) for _ in self.options)
    def __repr__(self):
        return "lt%d, sl=%d%s" % (self.linktype, self.snaplen, self.optstr())


class CommentOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "CMT:'%s'" % escape(self.txt)
class HardwareOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "HW:'%s'" % escape(self.txt)
class OSOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "OS:'%s'" % escape(self.txt)
class ApplOption:
    def __init__(self, data):
        self.txt = data.decode('utf-8')
    def __repr__(self):
        return "APP:'%s'" % escape(self.txt)

class SectionHeader:
    """
00000000: 0a 0d 0d 0a 9c 00 00 00 4d 3c 2b 1a 01 00 00 00
00000010: ff ff ff ff ff ff ff ff 

00000018:                         02 00 37 00 49 6e 74 65  ..........7.Inte
00000020: 6c 28 52 29 20 43 6f 72 65 28 54 4d 29 20 69 37  l(R) Core(TM) i7
00000030: 2d 34 38 35 30 48 51 20 43 50 55 20 40 20 32 2e  -4850HQ CPU @ 2.
00000040: 33 30 47 48 7a 20 28 77 69 74 68 20 53 53 45 34  30GHz (with SSE4
00000050: 2e 32 29 00 

00000054:             03 00 19 00 4c 69 6e 75 78 20 34 2e  .2).....Linux 4.
00000060: 32 30 2e 36 2d 61 72 63 68 31 2d 31 2d 41 52 43  20.6-arch1-1-ARC
00000070: 48 00 00 00 

00000074:             04 00 19 00 44 75 6d 70 63 61 70 20  H.......Dumpcap 
00000080: 28 57 69 72 65 73 68 61 72 6b 29 20 32 2e 36 2e  (Wireshark) 2.6.
00000090: 36 00 00 00

00000094:             00 00 00 00 9c 00 00 00 


    """
    def __init__(self, data):
        byteorder, majorv, minorv, self.sectionsize = struct.unpack("<LHHQ", data[:16])
        if byteorder!=0x1A2B3C4D:
            raise Exception("unsupported byteorder")

        self.version = (majorv, minorv)
        self.options = list( self.decodeoptions(data[16:]) )

    def decodeoptions(self, data):
        o = 0
        while o < len(data):
            optcode, optlen, = struct.unpack_from("<HH", data, o)
            o += 4
            optdata = data[o:o+optlen]
            o += roundup(optlen, 4)
            if optcode==0:
                break
            elif optcode==1:
                yield CommentOption(optdata)
            elif optcode==2:
                yield HardwareOption(optdata)
            elif optcode==3:
                yield OSOption(optdata)
            elif optcode==4:
                yield ApplOption(optdata)
            else:
                print("unknown option", optcode)


    def optstr(self):
        if not self.options:
            return ""
        return "\n" + "\n".join(repr(_) for _ in self.options)
    def __repr__(self):
        return "v%s, ss=%d%s" % ("%d.%d"%self.version, self.sectionsize, self.optstr())

class PcapNgReader:
    def __init__(self, fh):
        self.fh = fh

    def __iter__(self):
        return self
    def next(self):
        return self.__next__()
    def __next__(self):
        off = self.fh.tell()
        blkhdr = self.fh.read(8)
        if not blkhdr:
            raise StopIteration()
        blktype, blksize = struct.unpack("<LL", blkhdr)
        blockdata = self.fh.read(blksize-12)
        blkhdr2 = self.fh.read(4)
        blksize2, = struct.unpack("<L", blkhdr2)
        if blksize2!=blksize:
            raise  Exception("framing error")

        if blktype==6:
            return EnhancedPacket(blockdata)
        elif blktype==1:
            return InterfaceDesc(blockdata)
        elif blktype==0x0a0d0d0a:
            return SectionHeader(blockdata)
        else:
            return UnknownEntry(blktype, blockdata)

class UnknownEntry:
    def __init__(self, type, data):
        self.type = type
        self.data = data
    def __repr__(self):
        return "unknown(%08x): %s" % (self.type, self.data.hex())


def main():
    import argparse
    parser = argparse.ArgumentParser(description='pcapng dumper')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--usb', '-u', action='store_true', help='format usbmon captures')
    parser.add_argument('FILE', nargs='+')
    args = parser.parse_args()

    for filename in args.FILE:
        print("==>", filename, "<==")
        with open(filename,"rb") as fh:
            for pkt in PcapNgReader(fh):
                if isinstance(pkt, EnhancedPacket):
                    if args.usb:
                        pkt.printusb()
                    else:
                        print(pkt)
                    #f pkt.data[10:13] in (b'\x80\x03\x01',b'\x81\x03\x01',b'\x00\x03\x01',b'\x01\x03\x01',):
                    #   if len(pkt.data)>64:
                    #       print(pkt)
                elif args.verbose:
                    print(pkt)
     
if __name__ == '__main__':
    main()

