"""Linux-only packet checks. Run in a disposable NET_ADMIN, --network none container."""
import ipaddress
import socket
import struct
import subprocess
import sys
import time
sys.path.insert(0,'/backend')
from guest_network import guard, mac

CONFIG={'node':'pve1','vm_first':1100,'ip_first':'10.10.10.20','gateway':'10.10.10.1','public_network':{'pool_id':'test','cidr':'198.51.100.0/29','gateway':'198.51.100.1','host_ip':'198.51.100.2','bridge':'vmbr0','reserved':[]}}
ROW={'slot':0,'order_id':1,'client_id':2};LEASE={'address':'198.51.100.3'}
def run(*args,input=None):
 result=subprocess.run(args,input=input,text=True,capture_output=True)
 if result.returncode:print(result.stderr,file=sys.stderr);result.check_returncode()
 return result
def pair(bridge,tap,peer):
 run('ip','link','add',tap,'type','veth','peer','name',peer);run('ip','link','set',tap,'master',bridge)
 for link in (tap,peer):run('ip','link','set',link,'up')
def hardware(address):return bytes.fromhex(address.replace(':',''))
def checksum(value):
 words=struct.unpack('!'+str(len(value)//2)+'H',value);n=sum(words);n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return (~n)&65535

def ipv4(src,dst):
 header=struct.pack('!BBHHHBBH4s4s',0x45,0,28,1,0,64,1,0,socket.inet_aton(src),socket.inet_aton(dst))
 header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
 return header+b'\x08\x00\xf7\xff\x00\x00\x00\x00'
def arp(src,dst,source_mac):return struct.pack('!HHBBH',1,0x0800,6,4,1)+hardware(source_mac)+socket.inet_aton(src)+bytes(6)+socket.inet_aton(dst)
def packet(source_mac,kind,payload,dest_mac):return hardware(dest_mac)+hardware(source_mac)+struct.pack('!H',kind)+payload

def delivered(sender,receiver,frame):
 receiver.setblocking(False)
 while True:
  try:receiver.recv(65535)
  except BlockingIOError:break
 sender.send(frame);receiver.settimeout(.15)
 try:
  while True:
   if receiver.recv(65535)==frame:return True
 except TimeoutError:return False

def channel(name):
 value=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));value.bind((name,0));return value

run('ip','link','add','br0','type','bridge');run('ip','link','set','br0','up')
pair('br0','tap1100i1','guestpub');pair('br0','uplink0','wan')
for link in ('tap1100i1','uplink0'):run('bridge','link','set','dev',link,'learning','off')
WAN='02:aa:aa:aa:aa:aa'
run('bridge','fdb','replace',WAN,'dev','uplink0','master','static')
run('bridge','fdb','replace',mac(ROW,1),'dev','tap1100i1','master','static')
# Bridge netfilter conntrack must run before our ingress established-reply rule.
rules=guard(ROW,LEASE,CONFIG)
run('nft','--check','-f','-',input=rules);run('nft','-f','-',input=rules)
guest,wan=channel('guestpub'),channel('wan')
cases=[('public internet',mac(ROW,1),0x0800,ipv4('198.51.100.3','8.8.8.8'),True),
 ('spoofed IP',mac(ROW,1),0x0800,ipv4('198.51.100.4','8.8.8.8'),False),
 ('spoofed MAC','02:11:22:33:44:55',0x0800,ipv4('198.51.100.3','8.8.8.8'),False),
 ('host services',mac(ROW,1),0x0800,ipv4('198.51.100.3','198.51.100.2'),False),
 ('private billing',mac(ROW,1),0x0800,ipv4('198.51.100.3','10.10.10.11'),False),
 ('gateway ARP',mac(ROW,1),0x0806,arp('198.51.100.3','198.51.100.1',mac(ROW,1)),True),
 ('peer ARP',mac(ROW,1),0x0806,arp('198.51.100.3','198.51.100.4',mac(ROW,1)),False),
 ('VLAN injection',mac(ROW,1),0x8100,b'\x00\x05\x08\x00'+ipv4('198.51.100.3','8.8.8.8'),False),
 ('IPv6 bypass',mac(ROW,1),0x86dd,b'\x60'+bytes(63),False)]
for name,source,kind,payload,expected in cases:
 actual=delivered(guest,wan,packet(source,kind,payload,WAN));assert actual==expected,(name,actual,expected);print('PASS:',name)
run('nft','-f','-',input='delete table bridge safehost_1100\n'+guard(ROW,{'address':'198.51.100.4'},CONFIG))
for destination,expected in [('198.51.100.3',False),('198.51.100.4',True)]:
 actual=delivered(wan,guest,packet(WAN,0x0800,ipv4('8.8.8.8',destination),mac(ROW,1)))
 assert actual==expected,('address reuse egress',destination,actual);print('PASS: egress address',destination,expected)
print('PASS: isolated Linux bridge packet policies')

# Host-initiated readiness SSH may return; guests cannot initiate host connections.
run('ip','link','add','br1','type','bridge');run('ip','link','set','br1','up')
pair('br1','tap1100i0','guestpriv');pair('br1','uplink1','hostpeer')
HOST='02:bb:bb:bb:bb:bb'
run('bridge','fdb','replace',HOST,'dev','uplink1','master','static')
run('bridge','fdb','replace',mac(ROW,0),'dev','tap1100i0','master','static')
guestpriv,hostpeer=channel('guestpriv'),channel('hostpeer')
def tcp4(src,dst,sport,dport,flags):
 tcp=struct.pack('!HHIIBBHHH',sport,dport,1,2 if flags==18 else 0,0x50,flags,65535,0,0)
 pseudo=socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,6,len(tcp))
 tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
 header=struct.pack('!BBHHHBBH4s4s',0x45,0,40,5,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
 return header[:10]+struct.pack('!H',checksum(header))+header[12:]+tcp
syn=packet(HOST,0x0800,tcp4('10.10.10.1','10.10.10.20',50000,22,2),mac(ROW,0))
assert delivered(hostpeer,guestpriv,syn),'Host readiness SYN blocked'
reply=packet(mac(ROW,0),0x0800,tcp4('10.10.10.20','10.10.10.1',22,50000,18),HOST)
assert delivered(guestpriv,hostpeer,reply),'Readiness SYNACK blocked'
attack=packet(mac(ROW,0),0x0800,tcp4('10.10.10.20','10.10.10.1',22,50001,2),HOST)
assert not delivered(guestpriv,hostpeer,attack),'Guest initiated access to host'
print('PASS: private readiness return and guest-to-host isolation')
# Released addresses remain denied if an archived public NIC is manually reattached.
released={**LEASE,'state':'released'}
run('nft','-f','-',input='delete table bridge safehost_1100\n'+guard(ROW,released,CONFIG))
assert not delivered(guest,wan,packet(mac(ROW,1),0x0800,ipv4('198.51.100.3','8.8.8.8'),WAN))
print('PASS: archived guest cannot transmit released address')

# Boot regenerates rules from canonical SQLite, not stale .nft snapshots.
import tempfile,json,sqlite3
from unittest.mock import patch
from pathlib import Path
from urllib.parse import quote
from ipam import Ipam
from expand_pool import fingerprint
from network_boot import reload_guards
from guest_network import remove_guard
with tempfile.TemporaryDirectory() as root:
 root=Path(root);state=root/'state';state.mkdir();configs=root/'pve';configs.mkdir()
 config_file=root/'config.json';config_file.write_text(json.dumps(CONFIG));(state/'config.sha256').write_text(fingerprint(CONFIG))
 db=sqlite3.connect(state/'allocations.sqlite');db.row_factory=sqlite3.Row
 allocator=Ipam(db,{**CONFIG['public_network'],'enabled':True})
 owner='11111111-1111-4111-8111-111111111111';reference='22222222-2222-4222-8222-222222222222'
 lease=allocator.reserve(owner,reference);allocator.bind(owner,reference,lease['id'],1,2)
 spec={'plan':'mini','ssh_key':None,'network_mode':'public_ipv4'}
 db.execute('CREATE TABLE allocation(order_id INTEGER PRIMARY KEY,client_id INTEGER,slot INTEGER UNIQUE,spec TEXT,phase TEXT,reason TEXT,created_at TEXT)')
 db.execute('INSERT INTO allocation VALUES(1,2,0,?,"ready",NULL,NULL)',(json.dumps(spec),));db.commit()
 marker='safehost-billing:v1:order:1:client:2:'+fingerprint(spec)
 (configs/'1100.conf').write_text('#'+quote(marker,safe='')+'\n')
 with patch('network_boot.subprocess.check_output',return_value=json.dumps({'description':marker})):
  reload_guards(config_file,state,configs)
 assert delivered(guest,wan,packet(mac(ROW,1),0x0800,ipv4('198.51.100.3','8.8.8.8'),WAN))
 allocator.release_assigned(1,2,lease['id'],isolated=True)
 with patch('network_boot.subprocess.check_output',return_value=json.dumps({'description':marker})):
  reload_guards(config_file,state,configs)
 assert not delivered(guest,wan,packet(mac(ROW,1),0x0800,ipv4('198.51.100.3','8.8.8.8'),WAN))
 (configs/'1100.conf').write_text('#foreign VM\n')
 with patch('network_boot.subprocess.check_output',return_value=json.dumps({'description':'foreign VM'})):
  try:reload_guards(config_file,state,configs);raise AssertionError('Foreign VM accepted at boot')
  except ValueError:pass
 db.close()
remove_guard(1100)
assert delivered(guest,wan,packet(mac(ROW,1),0x0800,ipv4('198.51.100.3','8.8.8.8'),WAN))
print('PASS: canonical boot recovery, archive deny, foreign identity refusal, purge guard cleanup')
