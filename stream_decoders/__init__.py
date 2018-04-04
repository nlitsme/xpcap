class StreamDecoder:
    def __init__(self, ad):
        # 'ad' points to StreamAutoDetect object, so we can change to a different protocol after say 'websocket',
        # or starttls
        self.ad= ad
        self.peers= {}

