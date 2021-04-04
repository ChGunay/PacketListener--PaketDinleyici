import scapy.all as scapy
from scapy_http import http
import optparse

def get_interface():
    opt_object = optparse.OptionParser()
    opt_object.add_option("-i","--interface", dest = "iface", help="please enter interface")
    options = opt_object.parse_args()[0]
    
    if not options.iface:
        print("Enter invalid interface")
    return options

valid_options = get_interface()
interface = valid_options.iface

def listiner(interface):
    scapy.sniff(iface=interface, store=False,prn=analyze_packet  )

#prn=callback function


def analyze_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)
            