"""Builds the test captures in tests/data from ClientHellos sent by local
clients to a socket on 127.0.0.1 (OpenSSL 4.1 with ML-KEM, macOS curl,
Python 3.14, OpenSSL DTLS). Expected values in tests/fingerprints.rs come
from tshark 4.6 (tcp.reassemble_out_of_order:TRUE). Run from tests/data."""
import struct, socket
def csum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s>>16)+(s&0xffff); s+=s>>16; return (~s)&0xffff
def ipv4(src,dst,proto,payload):
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),1,0x4000,64,proto,0,socket.inet_aton(src),socket.inet_aton(dst))
    h=h[:10]+struct.pack('!H',csum(h))+h[12:]; return h+payload
def ipv6(src,dst,proto,payload):
    return struct.pack('!IHBB16s16s',6<<28,len(payload),proto,64,socket.inet_pton(socket.AF_INET6,src),socket.inet_pton(socket.AF_INET6,dst))+payload
def tcp(sp,dp,seq,flags,payload=b''):
    return struct.pack('!HHIIBBHHH',sp,dp,seq,1 if flags&0x10 else 0,5<<4,flags,65535,0,0)+payload
def udp(sp,dp,payload):
    return struct.pack('!HHHH',sp,dp,8+len(payload),0)+payload
def eth(ip, v6=False):
    return b'\x02\0\0\0\0\x02'+b'\x02\0\0\0\0\x01'+struct.pack('!H',0x86dd if v6 else 0x0800)+ip
def pktap(frame, ifname=b'en0', flags=2, pid=0, comm=b'', epid=0, ecomm=b'', dlt=1, pre=14):
    h=struct.pack('<III24sIIIIi20sIHHi20sII8s16s16s',156,1,dlt,ifname,flags,2,pre,0,pid,comm,0,6,0,epid,ecomm,0,6,b'\0'*8,b'\x11'*16,b'\x22'*16)
    assert len(h)==156, len(h)
    return h+frame
def write(path, linktype, pkts):
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,linktype))
        for i,p in enumerate(pkts):
            f.write(struct.pack('<IIII',1763300000+i,0,len(p),len(p))+p)
def dns_name(n): return b''.join(bytes([len(l)])+l.encode() for l in n.split('.'))+b'\0'
def dns_query(name,qt=1,qid=7): return struct.pack('!HHHHHH',qid,0x0100,1,0,0,0)+dns_name(name)+struct.pack('!HH',qt,1)
def dns_resp(name,ip,qid=7):
    q=dns_name(name)+struct.pack('!HH',1,1)
    return struct.pack('!HHHHHH',qid,0x8180,1,1,0,0)+q+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(ip)

ch_ossl=open('ch_openssl.bin','rb').read(); ch_curl=open('ch_curl.bin','rb').read(); ch_py=open('ch_python.bin','rb').read()

# 1. TCP reassembly: out of order, retransmission, IPv6
P=[]
c,s='10.0.0.2','198.51.100.7'
P.append(eth(ipv4(c,s,6,tcp(50001,443,1000,0x02))))
seg=[(0,700),(700,1400),(1400,len(ch_ossl))]
order=[1,0,0,2]   # segment 2 first, then 1, 1 again, then 3
for i in order:
    a,b=seg[i]; P.append(eth(ipv4(c,s,6,tcp(50001,443,1001+a,0x18,ch_ossl[a:b]))))
for k,(a,b) in enumerate([(0,600),(600,1200),(1200,len(ch_py))]):
    P.append(eth(ipv6('2001:db8::2','2001:db8::7',6,tcp(50002,8443,5000+a,0x18,ch_py[a:b])),True))
P.append(eth(ipv4(c,s,6,tcp(50003,443,9,0x18,ch_curl))))
write('tcp_split.pcap',1,P)

# 2. PKTAP: DNS answer -> named connection, HTTP Host, delegated socket
P=[]
P.append(pktap(eth(ipv4('10.0.0.2','10.0.0.1',17,udp(5353,53,dns_query('example.org')))),pid=90,comm=b'mDNSResponder'))
P.append(pktap(eth(ipv4('10.0.0.1','10.0.0.2',17,udp(53,5353,dns_resp('example.org','93.184.215.14')))),flags=1,pid=90,comm=b'mDNSResponder'))
P.append(pktap(eth(ipv4('10.0.0.2','93.184.215.14',6,tcp(50010,80,1,0x02))),pid=4242,comm=b'curl'))
P.append(pktap(eth(ipv4('10.0.0.2','93.184.215.14',6,tcp(50010,80,2,0x18,b'GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl\r\n\r\n'))),pid=4242,comm=b'curl'))
P.append(pktap(eth(ipv4('10.0.0.2','10.0.0.1',17,udp(50011,53,dns_query('dig.example.net',28)))),pid=4343,comm=b'dig'))
P.append(pktap(eth(ipv4('10.0.0.2','17.253.5.1',6,tcp(50012,443,1,0x18,ch_curl))),pid=500,comm=b'nsurlsessiond',epid=600,ecomm=b'softwareupdated',flags=2|4))
P.append(pktap(eth(ipv4('10.0.0.2','17.253.5.1',6,tcp(50013,443,1,0x18,b'\x16\x03\x01'+ch_ossl[3:]))),flags=1,pid=500,comm=b'nsurlsessiond'))  # inbound: must be skipped
write('pktap.pcap',258,P)

# 3. DTLS: OpenSSL fragments its ClientHello on loopback (2 datagrams for
#    DTLS 1.2, 8 for DTLS 1.3 with ML-KEM). The .bin files hold the first
#    flight as length-prefixed datagrams. DTLS 1.2 is sent twice (as after
#    a HelloVerifyRequest: reported once), DTLS 1.3 out of order.
def grams(path):
    b=open(path,'rb').read(); out=[]
    while b:
        n=struct.unpack('!H',b[:2])[0]; out.append(b[2:2+n]); b=b[2+n:]
    return out
P=[]
for g in grams('dtls12.bin')*2:
    P.append(eth(ipv4('10.0.0.2','198.51.100.9',17,udp(50020,4433,g))))
g13=grams('dtls13.bin'); g13=[g13[-1]]+g13[3:-1]+g13[:3]
for g in g13:
    P.append(eth(ipv4('10.0.0.2','198.51.100.9',17,udp(50021,4433,g))))
write('dtls.pcap',1,P)
print('ok')
