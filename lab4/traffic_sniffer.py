from scapy.all import IP, TCP, UDP, rdpcap

# 1. Opens the provided PCAP.
# 2. Prints the source IP, destination IP, protocol (TCP or UDP), and source/destination ports for the first 20 IPv4 TCP/UDP packets.
# 3. Counts the total TCP packets and total UDP packets in the capture.
# 4. Prints a clear summary at the end.

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

ipv4_tcp_udp = []
for pkt in packets:
    if IP in pkt and (TCP in pkt or UDP in pkt):
        ipv4_tcp_udp.append(pkt)

print("First 20 IPv4 TCP/UDP packets:")
for pkt in ipv4_tcp_udp[:20]:
    ip_layer = pkt[IP]

    if TCP in pkt:
        proto = "TCP"
        transport = pkt[TCP]
    elif UDP in pkt:
        proto = "UDP"
        transport = pkt[UDP]
    else:
        continue

    print(
        f"Source: {ip_layer.src} | Destination: {ip_layer.dst} | "
        f"Protocol: {proto} | Source port: {transport.sport} | "
        f"Destination port: {transport.dport}"
    )

tcp_packets = sum(1 for pkt in packets if IP in pkt and TCP in pkt)
udp_packets = sum(1 for pkt in packets if IP in pkt and UDP in pkt)

print(f"Total TCP packets: {tcp_packets}")
print(f"Total UDP packets: {udp_packets}")
print("Summary complete.")

