import ctypes, os, warnings
warnings.filterwarnings("ignore")
from ctypes import c_void_p, c_ulong, byref, create_string_buffer
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes
KENC=bytes.fromhex("404142434445464748494A4B4C4D4E4F")
KMAC=KENC
isd=bytes.fromhex("A000000151000000")

f=ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
ctx=c_void_p(); f.SCardEstablishContext(0,None,None,byref(ctx))
pcch=c_ulong(0); f.SCardListReaders(ctx,None,None,byref(pcch))
buf=create_string_buffer(pcch.value); f.SCardListReaders(ctx,None,buf,byref(pcch))
names=[x.decode() for x in buf.raw.split(b"\x00") if x]
class IO(ctypes.Structure): _fields_=[("p",c_ulong),("l",c_ulong)]

print("=== ...T=1 ...===")
h=c_void_p(); pr=c_ulong()
r=f.SCardConnect(ctx,names[0].encode(),2,2,byref(h),byref(pr))  # mask=2: T=1 ONLY
if r==0:
    print(f"T=1 ...proto={pr.value}")
else:
    print(f"T=1 reject...{hex(r & 0xffffffff)} — card T=0 only ...")

print()
print("=== ...T=0 + case-4 LOAD (Le=0x00) ===")
# ... T=0
if r==0: f.SCardDisconnect(h,0)
h=c_void_p(); pr=c_ulong()
r=f.SCardConnect(ctx,names[0].encode(),2,3,byref(h),byref(pr))
print(f"T=0: {hex(r)} proto={pr.value}")
if r!=0: exit(1)

def raw_tx(apdu):
    s=IO(pr.value,ctypes.sizeof(IO)); rv=IO(0,ctypes.sizeof(IO))
    send=create_string_buffer(bytes(apdu),len(apdu))
    rec=create_string_buffer(258); l=c_ulong(258)
    pl=c_ulong(ctypes.sizeof(IO))
    f.SCardTransmit(h,byref(s),send,c_ulong(len(apdu)),byref(rv),rec,byref(l),byref(pl))
    return rec.raw[:l.value]

def transmit(apdu,label=""):
    d=raw_tx(apdu); sw=d[-2:].hex().upper()
    while sw.startswith("61"):
        more=int(sw[2:],16) if sw[2:] else 16
        d2=raw_tx([0x00,0xC0,0x00,0x00,more])
        d=d[:-2]+d2[:-2]; sw=d2[-2:].hex().upper()
    while sw.startswith("6C"):
        le2=int(sw[2:],16)
        d=raw_tx(apdu[:-1]+[le2]); sw=d[-2:].hex().upper()
    print(f"{label:38s} -> SW {sw}")
    return sw,d[:-2]

def cbc3(key,data,iv=b'\x00'*8):
    e=Cipher(algorithms.TripleDES(key),modes.CBC(iv)).encryptor()
    return e.update(data)+e.finalize()
def des8(k,d):
    e=Cipher(algorithms.TripleDES(k*3),modes.ECB()).encryptor()
    return e.update(d)+e.finalize()
def pad80(d):
    t=(len(d)//8+1)*8
    r=bytearray(d+b'\x00'*(t-len(d))); r[len(d)]=0x80
    return bytes(r)
def mac_3des(key,data): return cbc3(key,pad80(data))[-8:]
def mac_des_3des(key,data):
    d=pad80(data)
    iv2=des8(key[:8],d[:8]) if len(d)>8 else b'\x00'*8
    return cbc3(key,d[-8:],iv2)[-8:]
def derive(base,usage,x2):
    return cbc3(base,bytes([1,usage])+x2+b'\x00'*12)
def des1_ecb(k16,b8):
    e=Cipher(algorithms.TripleDES(k16[:8]*3),modes.ECB()).encryptor()
    return e.update(b8)+e.finalize()
def mac_des_3des_gpp(key,data,iv):
    d=pad80(data)
    if len(d)>8:
        from cryptography.hazmat.primitives.ciphers import Cipher as C2
        e1=C2(algorithms.TripleDES(key[:8]*3),modes.CBC(iv)).encryptor()
        pre=e1.update(d[:-8])+e1.finalize()
        iv2=pre[-8:]
    else: iv2=iv
    e2=Cipher(algorithms.TripleDES(key),modes.CBC(iv2)).encryptor()
    return (e2.update(d[-8:])+e2.finalize())[-8:]

# ... handshake
sw,_=transmit([0x00,0xA4,0x04,0x00,8]+list(isd)+[0x00],"SELECT ISD")
if sw!="9000": print("ISD fail"); exit(1)
for attempt in range(6):
    hc=os.urandom(8)
    sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc),"INIT UPDATE")
    if sw=="9000" and len(resp)>=26: break
x2=resp[12:14]; cc=resp[12:20]
s_enc=derive(KENC,0x82,x2); s_mac=derive(KMAC,0x01,x2)
hcr=mac_3des(s_enc,cc+hc)
cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH")
if sw!="9000": print("EXT fail"); exit(1)
chain={"icv":cm}
def sx3(ins,p1,p2,data,label,le=None):
    iv=des1_ecb(s_mac,chain["icv"])
    newlc=len(data)+8
    mi=bytes([0x84,ins,p1,p2,newlc])+data
    c=mac_des_3des_gpp(s_mac,mi,iv)
    apdu=[0x84,ins,p1,p2,newlc]+list(data)+list(c)+([le] if le is not None else [])
    sw,r=transmit(apdu,label)
    chain["icv"]=c
    return sw,r

PKG=bytes.fromhex("F000000001DEAD")
# cleanup
sw,r=sx3(0xE4,0x00,0x80,bytes([0x4F,len(PKG)])+PKG,"DELETE")
# INSTALL for load
d_load=bytes([len(PKG)])+PKG+b"\x00\x00\x00\x00"
sw,r=sx3(0xE6,0x02,0x00,d_load,"INSTALL for load")
print()
if sw!="9000": print("IFL fail:",sw); exit(1)

# ... case-4 (Le=0x00) — how smacon!
import zipfile
z=zipfile.ZipFile('build222/cap/collarmac/javacard/collarmac.cap')
blob=b""
for comp in ["Header","Directory","Applet","Import","ConstantPool","Class","Method","StaticField","RefLocation"]:
    n=[x for x in z.namelist() if x.endswith(f"/{comp}.cap")]
    if n: blob+=z.read(n[0])
hdr=b'\xC4\x82'+bytes([len(blob)>>8,len(blob)&0xFF])
BS=0xDC
blocks=[hdr]+[blob[i:i+BS] for i in range(0,len(blob),BS)]
print(f"LOAD: {len(blocks)} block...Le=0x00 (case-4)")
for i,b in enumerate(blocks):
    last=0x80 if i==len(blocks)-1 else 0x00
    sw,r=sx3(0xE8,last,i,b,f"LOAD {i+1}/{len(blocks)} ({len(b)}B P1={last:02X} P2={i:02X} Le=00)",le=0x00)
    if sw!="9000": print(f"  ...{sw}"); break
if sw=="9000":
    print("\n*** LOAD ...CASE-4 (Le) ...Le! ***")
    L=bytes([len(PKG)])+PKG; A=bytes([8])+bytes.fromhex("F000000001DEAD01")
    d_inst=L+A+A+b"\x01\x00"+b"\x02\xC9\x00"+b"\x00"
    sw,r=sx3(0xE6,0x0C,0x00,d_inst,"INSTALL for install",le=0x00)
    print("INSTALL:",sw)
    if sw=="9000": print("*** ...***")
f.SCardDisconnect(h,0)
