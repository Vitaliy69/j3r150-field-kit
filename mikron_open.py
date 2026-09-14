import sys, os, warnings
warnings.filterwarnings("ignore")
sys.argv=["x","none"]
exec(open('scripts/gp_lite.py').read().split("# ---- stages ----")[0])
K=bytes.fromhex("404142434445464748494A4B4C4D4E4F")
KENC=KMAC=K
isd=bytes.fromhex("A000000151000000")
sw,fc=transmit([0x00,0xA4,0x04,0x00,len(isd)]+list(isd)+[0x00],"SELECT ISD")
if sw!="9000": sys.exit("ISD: "+sw)
print("FCI:",fc.hex().upper()[:100])
for attempt in range(6):
    hc=os.urandom(8)
    sw,resp=transmit([0x80,0x50,0x00,0x00,8]+list(hc)+([0x00] if attempt%2 else []),f"INIT UPDATE #{attempt+1}")
    if sw=="9000" and len(resp)>=26: break
else: sys.exit("INIT fail")
kvn=resp[10]
print(f"kvn={kvn:02X} scp={resp[11]:02X} | ...response {len(resp)}B: {resp.hex().upper()}")
x2=resp[12:14]; cc=resp[12:20]
s_enc=derive(KENC,0x82,x2); s_mac=derive(KMAC,0x01,x2)
hcr=mac_3des(s_enc,cc+hc)
cm=mac_des_3des(s_mac,bytes([0x84,0x82,0x01,0x00,0x10])+hcr)
sw,_=transmit([0x84,0x82,0x01,0x00,0x10]+list(hcr)+list(cm),"EXT AUTH (40..4F, case-3)")
if sw!="9000": sys.exit("EXT: "+sw)
print("*** SECURE CHANNEL OPEN — ...card ...key...***")
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
print("\n== ...==")
for p1,kind in [(0x80,"ISD"),(0x40,"apps/SD"),(0x20,"load files"),(0x10,"modules")]:
    sw,r=sx3(0xF2,p1,0x02,bytes([0x4F,0x00]),f"GET STATUS {kind}",le=0x00)
    if sw=="9000":
        print(f"{kind}: {r.hex().upper()}")
    else:
        print(f"{kind}: {sw}")
