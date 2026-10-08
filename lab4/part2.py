from scapy.all import IP

pkt = packets[0]
print("Contains IPv4?", IP in pkt)

if IP in pkt:
    print("Source IP:", pkt[IP].src)
    print("Destination IP:", pkt[IP].dst)

shown = 0
for pkt in packets:
    if IP in pkt:
        print(pkt[IP].src, "->", pkt[IP].dst)
        shown = shown + 1
        if shown == 5:
            break

if len(tcp_packets) > 0:
    pkt = tcp_packets[0]
    print("TCP flags:", pkt[TCP].flags)

if len(tcp_packets) > 0:
    pkt = tcp_packets[0]
    print("TCP flags:", pkt[TCP].flags)


shown = 0
for pkt in packets:
    if IP in pkt:
        print("Source:", pkt[IP].src, "Destination:", pkt[IP].dst,
              "Bytes:", len(pkt), "Time:", float(pkt.time))
        shown = shown + 1
        if shown == 5:
            break