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
class ISipRequestMessage(sip.Request):
    """
    """
    __hdr_defaults__ = {
        'method': 'INVITE',
        'uri': 'sip:user@example.com',
        'version': '2.0',
        'headers': {'To': '', 'From': '', 'Call-ID': '', 'CSeq': '', 'Contact': ''}
    }
    __methods = dict.fromkeys((
        'ACK', 'BYE', 'CANCEL', 'INFO', 'INVITE', 'MESSAGE', 'NOTIFY',
        'OPTIONS', 'PRACK', 'PUBLISH', 'REFER', 'REGISTER', 'SUBSCRIBE',
        'UPDATE'
    ))
__proto = 'SIP'


class ISipInterface():
    """
    """

    count = 0

    def __init__(self, name='test', source_ip="", source_port=5060, target_ip="", target_port=5060, msg_type="request",spi=3027309194,seq=0x12345678,key='',ack=0x12345678):
        """
        """
        self.name = name
        self.source_ip = source_ip
        self.source_port = source_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.msg_type = msg_type
        self.message = ISipRequestMessage() if msg_type.lower() == "request" else ISipResponseMessage()
        self.content=''
        self.ipv6 =inet6.IPv6(dst=target_ip,src=source_ip)if source_ip and target_ip else inet6.IPv6()
        self.tcp=inet.TCP(sport=source_port,dport=target_port,ack=ack) if source_port and target_port  else inet.TCP()
        self.esp=ipsec._ESPPlain(spi=spi,nh=0x06)
        self.key=key
        self.esp_seq=10
        self.tcp_seq=seq
    def set_pkt(self,tcp_pl='',fin=0):

    	msg=struct.pack('>I',self.esp.spi)+struct.pack('>I',self.esp.seq)+raw(self.tcp)+self.esp.padding+struct.pack('B',self.esp.padlen)+struct.pack('B',self.esp.nh)
    	msghash=hmac.new(key=binascii.a2b_hex(self.key),msg=msg)
    	if fin:
    		self.tcp.setfieldval('flags',0x18)
    		self.tcp.setfieldval('seq',self.tcp_seq)
    	else:
    		self.tcp.setfieldval('options',[('NOP',0x01),('NOP',0x01),('Timestamp',(581234,27257755))])
    		self.tcp.setfieldval('flags',0x010)
    		self.tcp.setfieldval('seq',self.tcp_seq)
    		self.tcp_seq+=1288
    	esp_tcp=self.tcp/tcp_pl
    	type(msghash.hexdigest()[:24])
    	self.esp.setfieldval('icv',binascii.a2b_hex(msghash.hexdigest()[:24]))
    	self.esp.setfieldval('seq',self.esp_seq)
    	self.esp.setfieldval('data',esp_tcp)
    	self.esp_seq+=1

    def get_pkt(self):
   		pkt=CookedLinux()/Dot1AD()/self.ipv6/self.esp
   		return pkt
   
    def set_content(self):
    	self.content=bytes('v=0\r\no=SAMSUNG-IMS-UE 1559222762435354 0 IN IP6 {0}\r\ns=SS VOIP\r\nc=IN IP6 {1}\r\nt=0 0\r\nm=audio 1234 RTP/AVP 116 107 118 96 111 110\r\nb=AS:49\r\nb=RS:612\r\nb=RR:1837\r\na=rtpmap:116 AMR-WB/16000/1\r\na=fmtp:116 mode-change-capability=2;max-red=220\r\na=rtpmap:107 AMR-WB/16000/1\r\na=fmtp:107 octet-align=1;mode-change-capability=2;max-red=220\r\na=rtpmap:118 AMR/8000/1\r\na=fmtp:118 mode-change-capability=2;max-red=220\r\na=rtpmap:96 AMR/8000/1\r\na=fmtp:96 octet-align=1;mode-change-capability=2;max-red=220\r\na=rtpmap:111 telephone-event/16000\r\na=fmtp:111 0-15\r\na=rtpmap:110 telephone-event/8000\r\na=fmtp:110 0-15\r\na=curr:qos local none\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\na=des:qos optional remote sendrecv\r\na=sendrecv\r\na=ptime:20\r\na=maxptime:240\r\n'.format(self.ipv6.src,self.ipv6.src).encode('utf-8'))
    	
    def get_invite(self):
        return self.message.pack()+self.content
    def send_pkt(self):
    	tcp_payload=self.get_invite()
    	pnum=int(len(tcp_payload)/1288)+1
    	if pnum==1:
    		self.set_pkt(tcp_pl=tcp_payload,fin=1)
    		#self.get_pkt().show()
    	elif pnum>1:
    		for x in range(0,pnum):
    			if x==pnum-1:
    				tcp_pl=tcp_payload[x*1288:]
    				fin=1
    			else:
    				tcp_pl=tcp_payload[x*1288:(x+1)*1288]
    				fin=0
    			self.set_pkt(tcp_pl=tcp_pl,fin=fin)
    			pkt=self.get_pkt()
                #print(raw(pkt))
    			pkt.show()
    			sendp(pkt,iface='rmnet_data1')
    	return

    def set_invite(self,src_ims='he.ims.mnc011.mcc460.3gppnetwork.org',src_imisdn='+8613849194907',max_for=70,dst_ims='he.ims.mnc011.mcc460.3gppnetwork.org',dst_imsisdn='+8618132605076',spi_c='3027309194',spi_s='3413185162',s_cell_id='46011190419b3b02'):
        """
        """
        self.set_content()
        self.message.uri = 'sip:{0};phone-context={1}@{2};user=phone'.format(dst_imsisdn,
							        										 src_ims,
							        										 dst_ims)
        self.message.method = 'INVITE'
        self.message.headers = {
        	'Via': 'SIP/2.0/TCP [{0}]:{1};branch={2};rport;transport=TCP'.format(self.ipv6.src,
                                                                 				  self.tcp.sport,
                                                                                  'z9hG4bK-524287-1---a91905a9ea9581eb'),
        	'Max-Forwards':'{0}'.format(max_for),
        	'Route':'<sip:[{0}]:{1};lr>'.format(self.ipv6.dst,
        										 self.tcp.dport),
        	'Proxy-Require': 'sec-agree',
			'Require': 'sec-agree',
			'Contact': '<sip:{0}@[{1}]:{2}>;+sip.instance="<urn:gsma:imei:35958307-812346-0>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";video'.format(src_imisdn,
				self.ipv6.src,
				self.tcp.sport
				),
			'To': '<sip:{0}@{1}>'.format(dst_imsisdn,
            							 dst_ims),
			'From': '<sip:{0}@{1}>;tag={2}'.format(src_imisdn,
            									   src_ims,
            									   'c31cdc3b'),
            'Call-ID': '{0}@{1}'.format('TZujGeaI11oxZM64MLen1w..',
            							self.ipv6.src),

            'CSeq': '1 INVITE',
            'Session-Expires': 1800,
            'Min-SE': 1800,
            'Accept': 'application/sdp, application/3gpp-ims+xml',
           	'Allow': 'INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK',
           	'Content-Type': 'application/sdp',
           	'Supported': 'timer, 100rel, precondition, gruu, sec-agree',
           	'Security-Verify': 'ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c={0};spi-s={1};port-c={2};port-s={3}'.format(spi_c,
           																																  spi_s,
           																																  self.tcp.sport,
           																																  self.tcp.dport),
           	'P-Preferred-Identity': '<sip:{0}@{1}>'.format(src_imisdn,
           													 src_ims),
           	'Accept-Contact': '*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"',
            'Content-Length': '0',
            'User-Agent': '{0}'.format('SM-G9550-G9550ZCS4CSB3 Samsung IMS 6.0'),
            'P-Early-Media': 'supported',
            'P-Preferred-Service':'urn:urn-7:3gpp-service.ims.icsi.mmtel',
            'P-Access-Network-Info': '3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={0}'.format(s_cell_id),
            'Content-Length': len(self.content),
            }
  	
  		
if __name__ == '__main__':
	key='a0e61dfc937db91838a0d4243b155882'
	spi=0xc44846a2
	ack=0x8d9ef030
	test_invite=ISipInterface(source_ip='240e:66:1001:c2ca:1:2:b28c:106b',target_ip='204e:66:1000::18',source_port=6201,target_port=9900,key=key,spi=spi,ack=ack)
	test_invite.set_invite(src_ims='bj.ims.mnc011.mcc460.3gppnetwork.org',src_imisdn='+8617310733810',max_for=70,dst_ims='bj.ims.mnc011.mcc460.3gppnetwork.org',dst_imsisdn='+8613849194907',spi_c=0x00018145,spi_s=spi,s_cell_id='46011190419b3b01')
	test_invite.send_pkt()