class Packet:
    def __init__(self, ip_src,ip_dst,dst_port,flags,seq,ack):
        self.ip_src=ip_src
        self.ip_dst=ip_dst
        self.dst_port=dst_port
        self.flags=flags
        self.seq=seq
        self.ack=ack

    def __del__(self):
        # Garbage collection
        class_name=self.__class__.__name__