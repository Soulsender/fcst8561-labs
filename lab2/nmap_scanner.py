import nmap

target = input("Enter target: ")

start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))
open_ports = []

def validate_port(port: int):
    return 1 <= port <= 65535

scanner = nmap.PortScanner()

scanner.scan(
    target,
    f"{start_port}-{end_port}"
)

if not validate_port(start_port) and not validate_port(end_port):
    print("Invalid port")
    exit(1)

print(f"Scan results for {target}")

for protocol in scanner[target].all_protocols():
    ports = scanner[target][protocol].keys()

    for port in sorted(ports):
        port_info = scanner[target][protocol][port]
        service = port_info.get("name")
        
        if port_info.get("state") == "open":
            print(f"Port {port} is OPEN using {service}")
            open_ports.append(port)
        # elif port_info.get("state") == "closed":
        #     print(f"Port {port} is CLOSED")

if open_ports:
    print("Open port(s) found:", len(open_ports))
else:
    print("No open ports found in the range.")

