from collections import defaultdict

from scapy.all import IP, TCP, UDP, rdpcap

window_seconds = 5.0
alert_threshold = 20

pcap_path = "botnet-capture-20110812-rbot.pcap"
packets = rdpcap(pcap_path)

recent_timestamps = defaultdict(list)
alerted_ips = set()
tcp_packets = 0
udp_packets = 0

for pkt in sorted(packets, key=lambda p: float(p.time)):
    if IP not in pkt:
        continue

    if TCP in pkt:
        tcp_packets += 1
    elif UDP in pkt:
        udp_packets += 1
    else:
        continue

    src_ip = pkt[IP].src
    current_time = float(pkt.time)
    timestamps = recent_timestamps[src_ip]

    timestamps[:] = [t for t in timestamps if t > current_time - window_seconds]
    timestamps.append(current_time)

    if len(timestamps) > alert_threshold and src_ip not in alerted_ips:
        print(
            f"ALERT: {src_ip} sent {len(timestamps)} IPv4 TCP/UDP packets "
            f"within {window_seconds} seconds."
        )
        alerted_ips.add(src_ip)

print(f"Total TCP packets: {tcp_packets}")
print(f"Total UDP packets: {udp_packets}")
print(f"Suspicious IPs: {len(alerted_ips)}")
