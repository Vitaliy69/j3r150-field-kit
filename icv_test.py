import sys, os, warnings, zipfile
warnings.filterwarnings("ignore")
sys.argv=["x","none"]
exec(open('scripts/gp_lite.py').read().split("# ---- stages ----")[0])
K=bytes.fromhex("404142434445464748494A4B4C4D4E4F"); KENC=KMAC=K
isd=bytes.fromhex("A000000151000000")
sw,_=transmit([0x00,0xA4,0x04,0x00,len(isd)]+list(isd)+[0x00],"SELECT ISD")
if sw!="9000": sys.exit("ISD: "+sw)
for attempt in range(6):
    hc=os.urandom(8)
    sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc)+([0x00] if attempt%2 else []),"INIT UPDATE")
    if sw=="9000" and len(resp)>=26: break
x2=resp[12:14]; cc=resp[12:20]
s_enc=derive(KENC,0x82,x2); s_mac=derive(KMAC,0x01,x2)
hcr=mac_3des(s_enc,cc+hc)
cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH")
if sw!="9000": sys.exit("EXT: "+sw)
print("channel ...EXT_AUTH_MAC =",cm.hex().upper())
# cleanup
for pkg in [PKG_AID, bytes.fromhex("F000000002BEEF")]:
    iv=des1_ecb(s_mac,cm)
    mi=bytes([0x84,0xE4,0x00,0x80,len(pkg)+2+8])+bytes([0x4F,len(pkg)])+pkg+b"\x00"
    macx=mac_des_3des_gpp(s_mac,mi,iv)
    sw,_=transmit([0x84,0xE4,0x00,0x80,len(pkg)+2+8]+list(bytes([0x4F,len(pkg)])+pkg+b"\x00")+list(macx),"DELETE")
    print("DELETE:",sw)
# ... sx3
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
sw,r=sx3(0xE6,0x02,0x00,bytes([len(PKG_AID)])+PKG_AID+b"\x00\x00\x00\x00","INSTALL for load")
print("IFL:",sw)
if sw!="9000": sys.exit()
z=zipfile.ZipFile('build222/cap/collarmac/javacard/collarmac.cap')
NO_DESC=["Header","Directory","Applet","Import","ConstantPool","Class","Method","StaticField","RefLocation"]
blob=b""
for comp in NO_DESC:
    n=[x for x in z.namelist() if x.endswith(f"/{comp}.cap")]
    if n: blob+=z.read(n[0])
hdr=b'\xC4\x82'+bytes([len(blob)>>8,len(blob)&0xFF])
print(f"CAP: {len(blob)}B, TLV hdr: {hdr.hex().upper()}")
BS=0xDC
# ... 1 — header
sw,r=sx3(0xE8,0x00,0x00,hdr,"LOAD block 1 (header)")
print("Block 1:",sw)
if sw!="9000": sys.exit("Block 1 failed")
mac1=chain["icv"]  # ... 1
print("MAC_1:",mac1.hex().upper())
# ...
chunk=blob[:BS]
mi2=bytes([0x84,0xE8,0x00,0x01,len(chunk)+8])+chunk
for name,iv in [
    ("A: ECB(mac1)", des1_ecb(s_mac,mac1)),
    ("B: mac1 raw",  mac1),
    ("C: zeros",     b'\x00'*8),
    ("D: ECB(cm_ext)",des1_ecb(s_mac,cm)),
]:
    mac2=mac_des_3des_gpp(s_mac,mi2,iv)
    apdu2=[0x84,0xE8,0x00,0x01,len(chunk)+8]+list(chunk)+list(mac2)
    sw2,r2=transmit(apdu2,f"LOAD block 2 ({name})")
    print(f"  {name}: {sw2}")
    if sw2=="9000":
        print(f"  >>> {name} ...block 3...")
        chain["icv"]=mac2
        chunk2=blob[BS:BS*2]
        sw3,r3=sx3(0xE8,0x00,0x02,chunk2,f"LOAD block 3")
        print(f"  Block 3: {sw3}")
        break
    if sw2 not in ("644F","6982"):
        print(f"  (...SW: {sw2} — ...")
        break
