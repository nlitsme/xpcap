import re

class HttpDecoder:
    def __init__(self, ad):
# 'ad' points to StreamAutoDetect object, so we can change to a different protocol
# after for example 'websocket' or starttls
        self.ad= ad
        self.peers= {}
        self.inhdr= True
    @staticmethod
    def isvaliddata(data, ofs, last):
        return re.match(r'[a-zA-Z]+\s+\S+\s+[A-Z]+/\d\.\d', data[ofs:last])
    def handle(self, src, data, ofs, last):
        if not src in self.peers:
            self.peers[src]= len(self.peers)
        if not self.inhdr:
            return
        i= data.find("\r\n\r\n", ofs)
        if i>=0 and i<last:
            data= data[ofs:i]
            self.inhdr= False
        print "http: %s" % data
        # todo: split stream in hdrs, content


toplevel=HttpDecoder
