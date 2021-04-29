import scapy.all as scapy
import nmap

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        return clients_list

    def print_result(results_list):
        print("IP\t\t\tMAC Address\n-------------")
        for client in results_list:
            print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan("103.16.25.10/24")
print("Available devices in the network:")
print("IP" + " "*18+"MAC")

