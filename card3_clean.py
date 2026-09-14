import sys, os, warnings
warnings.filterwarnings("ignore")
sys.argv=["x","none"]
exec(open('scripts/gp_lite.py').read().split("# ---- stages ----")[0])
BATCH_ENC=bytes.fromhex("90379A3E7116D455E55F9398736A01CA")
BATCH_MAC=bytes.fromhex("473F36161A7F7F60CC3A766EA4BE5247")
FACT=bytes.fromhex("404142434445464748494A4B4C4D4E4F")
isd=bytes.fromhex("A000000151000000")
sw,r=transmit([0x00,0xA4,0x04,0x00,len(isd)]+list(isd)+[0x00],"SELECT ISD")
print("ISD SELECT:",sw)
# ...
hc=os.urandom(8)
sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc),"INIT UPDATE ()")
print("...",sw,"| len:",len(resp),"| kvn:",hex(resp[10]) if len(resp)>11 else "?","| scp:",hex(resp[11]) if len(resp)>12 else "?")
x2=resp[12:14] if len(resp)>13 else b"\x00\x00"; cc=resp[12:20] if len(resp)>=20 else b"\x00"*8
s_mac=None
kvn_probe=resp[10] if len(resp)>11 else 0
plan=[("",FACT,FACT)] if kvn_probe!=0xFF else [("",BATCH_ENC,BATCH_MAC)]
print("...key...kvn-...",[p[0] for p in plan])
for lbl,KENC,KMAC in plan:
    s_enc=derive(KENC,0x82,x2); s_mac_try=derive(KMAC,0x01,x2)
    try:
        hcr=mac_3des(s_enc,cc+hc)
    except Exception:
        continue
    cm=mac_des_3des(s_mac_try,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
    sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),f"EXT AUTH ({lbl})")
    print(f"EXT AUTH {lbl}:",sw)
    if sw=="9000":
        s_mac=s_mac_try; chain={"icv":cm}; break
if s_mac is None: sys.exit("...")
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
for p1,kind in [(0x40,"apps"),(0x20,"load files")]:
    sw,r=sx3(0xF2,p1,0x02,bytes([0x4F,0x00]),f"GET STATUS {kind}",le=0x00)
    print(f"{kind}:",r.hex().upper()[:100])
d_load=bytes([len(PKG_AID)])+PKG_AID+bytes([len(SD)])+SD+b"\x00\x00\x00"
sw,r=sx3(0xE6,0x02,0x00,d_load,"INSTALL for load",le=0x00)
if sw!="9000":
    # ... 2.2.1!)
    d_load2=bytes([len(PKG_AID)])+PKG_AID+bytes([len(SD)])+SD+b"\x00\x00"
    sw,r=sx3(0xE6,0x02,0x00,d_load2,"INSTALL for load (2.2.1 4-)",le=0x00)
    if sw!="9000":
        d_load3=bytes([len(PKG_AID)])+PKG_AID+b"\x00\x00"
        sw,r=sx3(0xE6,0x02,0x00,d_load3,"INSTALL for load ( SD)",le=0x00)
print("IFL:",sw)
if sw=="9000":
    blob=cap_stream(CAP_PATH); n=len(blob)
    tlv=b'\xC4\x82'+bytes([n>>8,n&0xFF])+blob
    BS=247; blocks=[tlv[i:i+BS] for i in range(0,len(tlv),BS)]
    for i,b in enumerate(blocks):
        last=0x80 if i==len(blocks)-1 else 0x00
        sw,r=sx3(0xE8,last,i,b,f"LOAD {i+1}/{len(blocks)}",le=0x00)
        if sw!="9000": sys.exit("LOAD: "+sw)
    L=bytes([len(PKG_AID)])+PKG_AID; A=bytes([len(APP_AID)])+APP_AID
    for lbl,d in [("-",L+A+bytes([len(SD)])+SD+b"\x01\x00"+b"\x02\xC9\x00"),
                  ("GPPro-min",L+A+A+b"\x03\x00\x00\x00"+b"\x02\xC9\x00"),
                  ("std",L+A+b"\x00\x00\x00\x00\x00")]:
        sw,r=sx3(0xE6,0x0C,0x00,d,f"INSTALL-install ({lbl})",le=0x00)
        if sw=="9000": break
    print("INSTALL:",sw)
    if sw=="9000":
        print("\n*** ...CARD ...install pipeline ***")
        s2,r2=transmit([0x00,0xA4,0x04,0x00,len(APP_AID)]+list(APP_AID)+[0x00],"SELECT applet")
        print("SELECT:",s2)
        if s2=="9000":
            from cryptography.hazmat.primitives.ciphers.mac import CMAC
            from cryptography.hazmat.primitives.ciphers import algorithms as _a
            def cmac(k,dd):
                c=CMAC(_a.AES(k)); c.update(dd); return c.finalize()
            TK=bytes.fromhex("404142434445464748494A4B4C4D4E4F"); DK=bytes.fromhex("000102030405060708090A0B0C0D0E0F")
            ch=bytes.fromhex("5142434445464748")
            transmit([0x80,0x32,0x00,0x00,len(ch)]+list(ch),"MAC  perso (6985?)")
            wrap=DK+cmac(TK,DK)
            transmit([0x80,0x40,0x00,0x00,len(wrap)]+list(wrap),"PERSONALIZE 0x40")
            s5,r5=transmit([0x80,0x32,0x00,0x00,len(ch)]+list(ch),"MAC 0x32")
            exp=cmac(DK,ch).hex().upper()
            print("card:",r5.hex().upper(),"\n...",exp,"\n","*** ...TUTORIAL ...***" if r5.hex().upper()==exp else "no")
