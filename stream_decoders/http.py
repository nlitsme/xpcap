import re

from stream_decoders import StreamDecoder

class HttpDecoder(StreamDecoder):
    def __init__(self, ad):
        StreamDecoder.__init__(self, ad)
        self.inhdr= [ True, True ]
    @staticmethod
    def isvaliddata(data, ofs, last):
        return re.match(r'[a-zA-Z]+\s+\S+\s+[A-Z]+/\d\.\d', data[ofs:last])
    def handle(self, src, data, ofs, last):
        if not src in self.peers:
            self.peers[src]= len(self.peers)
        ix= self.peers[src]
        if not self.inhdr[ix]:
            return
        i= data.find("\r\n\r\n", ofs)
        if i>=0 and i<last:
            data= data[ofs:i]
            self.inhdr[ix]= False
        print("http: %s" % data)
        # todo: split stream in hdrs, content
        return last


toplevel=HttpDecoder
