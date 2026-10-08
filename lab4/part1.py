from scapy.all import TCP

pkt = packets[0]
print("Is this TCP?", TCP in pkt)

tcp_packets = []

for pkt in packets:
    if TCP in pkt:
        tcp_packets.append(pkt)

print("TCP packets:", len(tcp_packets))

for pkt in tcp_packets[:50]:
    print(pkt.summary())

if len(tcp_packets) > 0:
    pkt = tcp_packets[0]
    print("Source port:", pkt[TCP].sport)
    print("Destination port:", pkt[TCP].dport)

http_packets = []

for pkt in tcp_packets:
    if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
        http_packets.append(pkt)

print("TCP port 80 packets:", len(http_packets))
for pkt in http_packets[:50]:
    print(pkt.summary())

for pkt in packets:
    if UDP in pkt:
        if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            dns_packets.append(pkt)

print("UDP port 53 packets:", len(dns_packets))
for pkt in dns_packets[:50]:
    print(pkt.summary())