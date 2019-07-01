import os 
from scapy.all import *
import binascii
import utils
from scapy.layers import inet6
from scapy.layers import inet
from scapy.layers import ipsec
import binascii
import struct
import hmac
from dpkt import sip
import utils 

class ISipInterface():
    """
    """
    count = 0
    def __init__(self, name='test', source_ip="", source_port=5060, target_ip="", target_port=9900, spi=0,key=""):
        """
        """
        self.name = name
        self.source_ip = source_ip
        self.source_port = source_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.ipv6 =inet6.IPv6(dst=target_ip,src=source_ip,nh=0x32)if source_ip and target_ip else inet6.IPv6()
        self.tcp=inet.TCP(sport=source_port,dport=target_port,ack=0,chksum=0) if source_port and target_port  else inet.TCP()
        self.esp=ipsec._ESPPlain(spi=spi,nh=0x06,padding='\x01\x02',padlen=2)
        self.esp_seq=10
        self.tcp_seq=0x12344321
        self.key=key;
    def set_pkt(self,tcp_pl=''):
        msg=struct.pack('>I',self.esp.spi)+struct.pack('>I',self.esp.seq)+raw(self.tcp)+self.esp.padding+struct.pack('B',self.esp.padlen)+struct.pack('B',self.esp.nh)
        msghash=hmac.new(key=binascii.a2b_hex(self.key),msg=msg)
        
        self.tcp.setfieldval('chksum',0)
        esp_tcp=self.tcp/tcp_pl
        chksum_p=raw(self.ipv6)[8:24]+raw(self.ipv6)[24:40]+binascii.a2b_hex('0006')+struct.pack('>H',len(raw(esp_tcp)))+raw(esp_tcp)

        self.tcp.setfieldval('chksum',checksum(chksum_p))
        esp_tcp=self.tcp/tcp_pl
        self.tcp.setfieldval('chksum',checksum(chksum_p))
        self.tcp.setfieldval('flags','S')
        self.esp.setfieldval('icv',binascii.a2b_hex(msghash.hexdigest()[:24]))
        self.esp.setfieldval('seq',self.esp_seq)
        self.esp.setfieldval('data',esp_tcp)
        self.esp_seq+=1
    def create_pkt(self):
        self.set_pkt()
        
        pkt=self.ipv6/self.esp
        #pkt=Ether()/self.ipv6/self.esp
        return pkt
    def send_pkt(self):
        pkt=self.create_pkt()
        pkt.show()
        ans =sendp(pkt,verbose=False,iface='rmnet_data1')
def test_tcp():
    res=sr(IPv6(dst="2409:8000:2806:2210::")/TCP(dport=80,sport=17666,flags='S'),verbose=False)
    result=res[0].res
    print(result)

if __name__ == '__main__':
    spi=0xfca8a585
    key="66c13e1420147ed4f265db17e44a66e9"
    test_invite=ISipInterface(source_ip='2409:8100:523:b12d:2:2:db01:fd9e',target_ip='2409:8010:9410:1:1007:1007::',source_port=6201,target_port=9900,spi=spi,key=key)
    res=test_invite.send_pkt()
    print(res)
    #test_tcp()
