import sys, os, warnings
warnings.filterwarnings("ignore")
sys.argv=["x","none"]
exec(open('scripts/gp_lite.py').read().split("# ---- stages ----")[0])
KENC=KMAC=bytes.fromhex("404142434445464748494A4B4C4D4E4F")
isd=bytes.fromhex("A000000151000000")
sw,_=transmit([0x00,0xA4,0x04,0x00,len(isd)]+list(isd)+[0x00],"SELECT ISD")
for attempt in range(8):
    hc=os.urandom(8)
    sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc)+([0x00] if attempt%2 else []),"INIT UPDATE")
    if sw=="9000" and len(resp)>=26: break
x2=resp[12:14]; cc=resp[12:20]
s_enc=derive(KENC,0x82,x2); s_mac=derive(KMAC,0x01,x2)
hcr=mac_3des(s_enc,cc+hc)
cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH")
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
d_inst=(bytes([len(PKG_AID)])+PKG_AID+bytes([len(APP_AID)])+APP_AID+
        bytes([len(SD)])+SD+b"\x01\x00"+b"\x02\xC9\x00")
def try_install():
    return sx3(0xE6,0x0C,0x00,d_inst,"  INSTALL-install ",le=0x00)[0]
# ...
sw,r=sx3(0xF2,0x80,0x02,bytes([0x4F,0x00]),"ISD ",le=0x00)
print("ISD entry:",r.hex().upper()[:60])
import itertools
tried=False
for p1,st,mode in [(0x00,0x07,"data"),(0x40,0x07,"data"),(0x80,0x07,"data"),
                   (0x00,0x07,"p2"),(0x40,0x07,"p2"),(0x80,0x07,"p2"),
                   (0x00,0x0F,"data"),(0x80,0x0F,"p2"),
                   (0x04,0x07,"data"),(0x0C,0x0F,"data")]:
    lbl=f"SET STATUS P1={p1:02X} {mode}={st:02X}"
    if mode=="data":
        sw,r=sx3(0xF0,p1,0x00,bytes([st]),lbl)
    else:
        sw,r=sx3(0xF0,p1,st,b"",lbl)
    print(f"{lbl}: {sw}")
    if sw=="9000":
        tried=True
        i=try_install()
        print("  INSTALL ...",i)
        if i=="9000":
            print("*** ...***")
            s2,r2=transmit([0x00,0xA4,0x04,0x00,len(APP_AID)]+list(APP_AID)+[0x00],"SELECT")
            print("SELECT:",s2)
            break
    # ...
    sw2,r2=sx3(0xF2,0x80,0x02,bytes([0x4F,0x00]),"  ISD ",le=0x00)
    if "9F700107" in r2.hex().upper() or "9F70010F" in r2.hex().upper():
        print("  ...",r2.hex().upper()[:60])
        i=try_install()
        print("  INSTALL:",i)
        if i=="9000":
            s3,r3=transmit([0x00,0xA4,0x04,0x00,len(APP_AID)]+list(APP_AID)+[0x00],"SELECT")
            print("*** SELECT:",s3,"***")
            break
