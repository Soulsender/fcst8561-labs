import socket

target = input("Target: ")
start_port = int(input("Start port: "))
end_port = int(input("End port: "))
open_ports = []

def validate_port(port: int):
    return 1 <= port <= 65535

def resolve_host(target):
    try:
        target = socket.gethostbyname(target)
        print(f"Scanning: {target}")

    except socket.gaierror:
        print("Invalid hostname or IP address")
        exit(1)

def scan_port(target, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    sock.settimeout(0.5)

    result = sock.connect_ex(
        (target, port)
    )
    sock.close()

    if result == 0:
        return True
    else:
        return False


# main logic

# resolve host
resolve_host(target)

# validate ports
if not validate_port(start_port) and not validate_port(end_port):
    print("Invalid port")
    exit(1)
    
# scan
for port in range(start_port, end_port + 1):
    if scan_port(target, port):
        open_ports.append(port)
        try:
            service = socket.getservbyport(
                port,
                "tcp"
            )
        except OSError:
            service = "unknown"
        print(f"Port {port} is OPEN using {service}")
    # else:
    #     print(f"Port {port} is CLOSED")

# list open ports
if open_ports:
    print("Open port(s) found:", len(open_ports))
else:
    print("No open ports found in the range.")