from scapy.all import rdpcap, Raw

tcp_packets = []
http_packets = []
dns_packets = []
packets = rdpcap("botnet-capture-20110812-rbot.pcap")
print("File found")

pkt = packets[0]
print("Contains Raw payload?", Raw in pkt)

if Raw in pkt:
    print(repr(bytes(pkt[Raw].load)[:80]))
else:
    print("No Raw payload in this packet")

for pkt in packets:
    if Raw in pkt:
        print("Payload sample:", repr(bytes(pkt[Raw].load)[:80]))
        break

for pkt in packets:
    if Raw in pkt:
        sample = bytes(pkt[Raw].load)[:80]
        print(sample.decode("utf-8", errors="replace"))
        break

found = False
for pkt in packets:
    if Raw in pkt:
        data = bytes(pkt[Raw].load)
        if b"User-Agent:" in data:
            print("Possible plaintext HTTP header found")
            found = True
            break
if not found:
    print("No matching header found in the first 500 packets")