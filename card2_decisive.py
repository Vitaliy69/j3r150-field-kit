import sys, os, warnings, time
warnings.filterwarnings("ignore")
sys.argv=["x","none"]
exec(open('scripts/gp_lite.py').read().split("# ---- stages ----")[0])
# ... rc ----------
print("== ...JCOP IDENTIFY ==")
aid_ident=bytes.fromhex("A0000001674130")  # ... 00FF
for aid,label in [(aid_ident,"8B"),(bytes.fromhex("A000000167413000FF"),"9B+FF")]:
    send=create_string_buffer(bytes([0x00,0xA4,0x04,0x00,len(aid)]+list(aid)+[0x00]),5+len(aid)+1)
    rec=create_string_buffer(258); rl=c_ulong(258); pl=c_ulong(ctypes.sizeof(IO_REQ))
    rc=f.SCardTransmit(hCard,byref(send_pci),send,c_ulong(len(aid)+5),byref(recv_pci),rec,byref(rl),byref(pl))
    d=rec.raw[:rl.value]
    print(f"  IDENTIFY {label}: rc={hex(rc & 0xffffffff)} len={rl.value} | {d[:-2].hex().upper()[:70]}| SW {d[-2:].hex().upper()}")
    if rc==0 and d[-2:].hex().upper()=="9000" and rl.value>16:
        print("   fusion @14:",hex(d[14]),"->","UNFUSED" if d[14]==0 else "FUSED/CONFIGURED")
print()
# ...) ----------
KB_ENC=bytes.fromhex("90379A3E7116D455E55F9398736A01CA")
KB_MAC=bytes.fromhex("473F36161A7F7F60CC3A766EA4BE5247")
isd=bytes.fromhex("A000000151000000")
sw,_=transmit([0x00,0xA4,0x04,0x00,len(isd)]+list(isd)+[0x00],"SELECT ISD")
for attempt in range(8):
    hc=os.urandom(8)
    sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc)+([0x00] if attempt%2 else []),"INIT UPDATE")
    if sw=="9000" and len(resp)>=26: break
else: sys.exit("INIT fail")
kvn=resp[10]; print("kvn:",hex(kvn))
x2=resp[12:14]; cc=resp[12:20]
s_enc=derive(KB_ENC,0x82,x2); s_mac=derive(KB_MAC,0x01,x2)
hcr=mac_3des(s_enc,cc+hc)
cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH ()")
if sw!="9000": sys.exit("EXT: "+sw)
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
SD=bytes.fromhex("A000000151000000")
# ...)
sw,r=sx3(0xF2,0x40,0x02,bytes([0x4F,0x00]),"GET STATUS apps (card-2)",le=0x00)
print("apps:",r.hex().upper()[:120])
d_load=bytes([len(PKG_AID)])+PKG_AID+bytes([len(SD)])+SD+b"\x00\x00\x00"
sw,r=sx3(0xE6,0x02,0x00,d_load,"INSTALL for load",le=0x00)
if sw!="9000": sys.exit("IFL: "+sw)
blob=cap_stream(CAP_PATH); n=len(blob)
tlv=b'\xC4\x82'+bytes([n>>8,n&0xFF])+blob
BS=247; blocks=[tlv[i:i+BS] for i in range(0,len(tlv),BS)]
for i,b in enumerate(blocks):
    last=0x80 if i==len(blocks)-1 else 0x00
    sw,r=sx3(0xE8,last,i,b,f"LOAD {i+1}/{len(blocks)}",le=0x00)
    if sw!="9000": sys.exit("LOAD: "+sw)
d_inst=(bytes([len(PKG_AID)])+PKG_AID+bytes([len(APP_AID)])+APP_AID+
        bytes([len(SD)])+SD+b"\x01\x00"+b"\x02\xC9\x00")
sw,r=sx3(0xE6,0x0C,0x00,d_inst,"INSTALL for install ( CARD)",le=0x00)
print("\n...",sw)
if sw=="9000":
    print("*** ...CARD-2 ...install pipeline complete ***")
    s2,r2=transmit([0x00,0xA4,0x04,0x00,len(APP_AID)]+list(APP_AID)+[0x00],"SELECT")
    print("SELECT:",s2)
else:
    print("→ ...lock; ...PUT KEY ...")
    KDEK_B=bytes.fromhex("D3749ED4FF42FD58B39EEB562B017CD9")
    s_dek=derive(KDEK_B,0x81,x2)
    NEWK=bytes.fromhex("404142434445464748494A4B4C4D4E4F")
    def tdes_ecb(k,bb):
        e=Cipher(algorithms.TripleDES(k),modes.ECB()).encryptor(); return e.update(bb)+e.finalize()
    e=Cipher(algorithms.TripleDES(s_dek),modes.ECB()).encryptor()
    enc=e.update(NEWK)+e.finalize()
    kcv=tdes_ecb(NEWK,b'\x00'*8)[:3]
    data=bytes([0x01])+(bytes([0x80,len(enc)])+enc+bytes([3])+kcv)*3
    sw,r=sx3(0xD8,0x00,0x81,data,"PUT KEY ",le=0x00)
    print("PUT KEY:",sw)
    # ...
    for attempt in range(8):
        hc=os.urandom(8)
        sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc)+([0x00] if attempt%2 else []),"INIT UPDATE v2")
        if sw=="9000" and len(resp)>=26: break
    x2=resp[12:14]; cc=resp[12:20]
    s_enc=derive(NEWK,0x82,x2); s_mac=derive(NEWK,0x01,x2)
    hcr=mac_3des(s_enc,cc+hc)
    cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
    sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH v2")
    print("EXT AUTH v2:",sw)
    chain["icv"]=cm
    sw,r=sx3(0xE6,0x0C,0x00,d_inst,"INSTALL v2 ()",le=0x00)
    print("INSTALL v2:",sw)
