import scapy.all as scapy
from scapy_http import http
import optparse

def get_interface():#We get the interface name from the user.--Arayüz adını kullanıcıdan alıyoruz.
    opt_object = optparse.OptionParser()
    opt_object.add_option("-i","--interface", dest = "iface", help="please enter interface")
    options = opt_object.parse_args()[0]
    
    if not options.iface:
        print("Enter invalid interface")
    return options

valid_options = get_interface()
interface = valid_options.iface

def listiner(interface):
    scapy.sniff(iface=interface, store=False,prn=analyze_packet  )#Using the scapy.sniff feature, we listen for incoming packets. In addition, we synchronize the PRN value to the analysis function and direct the incoming packages there.--Scapy.sniff özelliğini kullanarak gelen paketleri dinliyoruz. Ayrıca PRN değerini analiz fonksiyonuna senkronize edip gelen paketleri oraya yönlendiriyoruz.

#prn=callback function


def analyze_packet(packet):#Using this function, we search for the layer we want in the layers of each packet that comes in.--Bu işlevi kullanarak, gelen her paketin katmanlarında istediğimiz katmanı ararız.
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)
            