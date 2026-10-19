import socket, hashlib, pyotp, logging
from scapy.all import IP, TCP, UDP, ICMP, rdpcap
from collections import defaultdict

HOST = "127.0.0.1"
PORT = 4444

# sample user database
users = {
    "jasper": {
        "password_hash": hashlib.sha256(
            "password".encode()
        ).hexdigest(),
        "totp_secret": "PQE6UTKFIXGL"
    }
}

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] @ %(asctime)s: %(message)s",
    handlers=[
        logging.FileHandler("server.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def packet_analyzer(client_socket):
    pcap_path = "FSCT8561_Operation_Sentinel_Traffic.pcap"
    client_socket.sendall(f"Using {pcap_path}".encode())
    packets = rdpcap(pcap_path)
    tcp_flags = {
        "FIN": 0x01,
        "SYN": 0x02,
        "RST": 0x04,
        "PSH": 0x08,
        "ACK": 0x10,
        "URG": 0x20,
        "ECE": 0x40,
        "CWR": 0x80,
    }

    recent_timestamps = defaultdict(list)
    alerted_ips = set()
    tcp_packets, udp_packets, icmp_packets, tcp_syn_packets, rst_syn_packets = 0, 0, 0, 0, 0
    for pkt in sorted(packets, key=lambda p: float(p.time)):
        if IP not in pkt:
            continue

        if TCP in pkt:
            tcp_packets += 1
            #  too many SYN flags can be evidence of a DDoS or scan
            if pkt[TCP].flags & tcp_flags["SYN"]:
                tcp_syn_packets += 1
            # too many RST flags can be evidence of a scan
            if pkt[TCP].flags & tcp_flags["RST"]:
                rst_syn_packets += 1
        elif UDP in pkt:
            udp_packets += 1
        # too many icmp packets can be evidence of a DDoS
        elif ICMP in pkt:
            icmp_packets += 1
        else:
            continue

        src_ip = pkt[IP].src
        current_time = float(pkt.time)
        timestamps = recent_timestamps[src_ip]

        timestamps[:] = [t for t in timestamps if t > current_time - window_seconds]
        timestamps.append(current_time)

        # look for a suspicious amount of packets in a short time
        window_seconds = 3.0
        alert_threshold = 20
        if len(timestamps) > alert_threshold and src_ip not in alerted_ips:
            client_socket.sendall(f"Host {src_ip} sent {len(timestamps)} packets within {window_seconds} seconds.".encode())
            alerted_ips.add(src_ip)

    client_socket.sendall(f"""
    Summary:
    Total TCP packets: {tcp_packets} with {tcp_syn_packets} SYNs & {rst_syn_packets} RSTs
    Total UDP packets: {udp_packets}
    Total ICMP packets: {icmp_packets}
    Suspicious IPs: {len(alerted_ips)}       
    """.encode())
    return

def authenticate(client_socket):
    message = client_socket.recv(1024).decode().strip()
    if not message:
        logger.info("Client disconnected during authentication")
        return False

    parts = message.split("|")

    if len(parts) != 3 or parts[0] != "AUTH":
        client_socket.sendall(b"ERROR|Invalid authentication request")
        logger.error("Unknown authentication mechanism")
        return False

    username = parts[1]
    password = parts[2]
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username not in users:
        client_socket.sendall(b"ACCESS_DENIED")
        logger.warning("Access denied to user")
        return False

    if password_hash != users[username]["password_hash"]:
        client_socket.sendall(b"ACCESS_DENIED")
        logger.warning("Access denied to user")
        return False

    client_socket.sendall(b"OTP_REQUIRED")

    message = client_socket.recv(1024).decode().strip()
    if not message:
        logger.info("Client disconnected during OTP verification")
        return False

    parts = message.split("|")

    if len(parts) != 2 or parts[0] != "OTP":
        client_socket.sendall(b"ERROR|Invalid OTP request")
        logger.error("Invalid OTP request")
        return False

    otp = parts[1]
    totp = pyotp.TOTP(users[username]["totp_secret"])

    if totp.verify(otp):
        client_socket.sendall(b"ACCESS_GRANTED")
        logger.info("Access granted to user")
        return True
    else:
        client_socket.sendall(b"ACCESS_DENIED")
        logger.warning("Access denied to user")
        return False

def menu(client_socket):
    client_socket.sendall("""

    Choose an operation:
    [0] - Port scan (client side)
    [1] - HTTP scan (client side)
    [2] - PCAP scan (server side)
    Type [exit] to quit.
    """.encode())
    message = client_socket.recv(1024).decode().strip()
    if not message:
        return None
    message = message.casefold()
    if message == "0":
        logger.info("Port scan selected")
        client_socket.sendall(b"PORTSCAN")
        return True
    elif message == "1":
        logger.info("HTTP scan selected")
        client_socket.sendall(b"HTTPSCAN")
        return True
    elif message == "2":
        logger.info("PCAP scan selected")
        client_socket.sendall(b"PCAPSCAN")
        packet_analyzer(client_socket)
        return True
    elif message == "exit":
        logger.info("Stopping server service...")
        client_socket.sendall(b"EXIT")
        return False
    else:
        logger.error("Invalid error selected")
        client_socket.sendall(b"ERROR|Invalid option")
        return True
    

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
except OSError as error:
    logger.critical("Could not start server on %s:%s: %s", HOST, PORT, error)
    server_socket.close()
    raise SystemExit(1)

print(f"Server listening on {HOST}:{PORT}")
logger.info("Server started")

server_running = True
try:
    while server_running:
        try:
            client_socket, address = server_socket.accept()
        except OSError as error:
            logger.error("Could not accept client connection: %s", error)
            break

        logger.info("Client connected from %s", address)

        try:
            if authenticate(client_socket):
                logger.info("User successfully authenticated")
                while True:
                    menu_result = menu(client_socket)
                    if menu_result is False:
                        server_running = False
                        break
                    if menu_result is None:
                        break
            else:
                logger.warning("Failed authentication")

        except Exception as error:
            logger.exception("Error while handling client %s", address)
            try:
                client_socket.sendall(f"ERROR|{error}".encode())
            except OSError:
                logger.debug("Could not send error to disconnected client %s", address)
        finally:
            client_socket.close()
except KeyboardInterrupt:
    logger.info("Server stopped by operator")
finally:
    server_socket.close()
    logger.info("Server socket closed")
