import tkinter as tk
from tkinter import Scrollbar
from scapy.all import sniff, IP, TCP, UDP
import socket
import threading

ip_domain_cache = {}

def get_domain_from_ip(ip):
    if ip in ip_domain_cache:
        return ip_domain_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
        ip_domain_cache[ip] = domain
        return domain
    except socket.herror:
        return "Unknown"
def get_protocol_name(protocol_number):
    try:
        protocol_name = socket.getservbyport(protocol_number)
        return protocol_name
    except OSError:
        return "Unknown"
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        src_domain = get_domain_from_ip(src_ip)
        dst_domain = get_domain_from_ip(dst_ip)

        prot = "Unknown"
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            trns = "TCP"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            trns = "UDP"
        sprotocol = get_protocol_name(sport)
        dprotocol = get_protocol_name(dport) 
        packet_info = f"protocol:{sprotocol}     Sprot({trns}:{sport})      Source IP({src_ip}  {src_domain})       dprotocol:{dprotocol}      Dprot({trns}:{dport})      Destination IP({dst_ip}  {dst_domain})"
        
        if packet_info not in packet_text.get("1.0", tk.END):
            packet_text.insert(tk.END, packet_info + "\n")  
            
            packet_text.yview_moveto(1)  

            root.update_idletasks()  

def start_sniffing():
    t = threading.Thread(target=sniff, kwargs={"iface": "eth0", "prn": packet_handler, "store": 0})
    t.start()
def close_app():
    ip_domain_cache.clear()
    root.destroy()

root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1600x1000")  

scrollbar = Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

packet_canvas = tk.Canvas(root, yscrollcommand=scrollbar.set)
packet_canvas.pack(expand=tk.YES, fill=tk.BOTH)

scrollbar.config(command=packet_canvas.yview)

packet_text = tk.Text(packet_canvas, wrap=tk.NONE, width=800, height=10000, yscrollcommand=scrollbar.set)
packet_text.pack(pady=10)

packet_canvas.create_window((0, 0), window=packet_text, anchor=tk.NW)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=5)

close_button = tk.Button(root, text="Close", command=close_app)
close_button.pack(pady=5)

root.mainloop()
