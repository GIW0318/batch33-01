class MediaDecodeGuard:
    def __init__(self, max_pixels=1000000, max_bytes=1000000):
        self.max_pixels = max_pixels
        self.max_bytes = max_bytes

    def inspect(self, header):
        return {}
