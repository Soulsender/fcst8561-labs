import ipaddress, socket, nmap, requests
from getpass import getpass

HOST = "127.0.0.1"
PORT = 4444

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def http_scan():
    BASE_URL = input("Enter URL of target: ")  
    headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Powered-By", "Server", ]

    try:
        probe_response = requests.get(BASE_URL, timeout=5)

        print(f"Server reported: {probe_response.status_code}")

        print("Testing Headers...")
        for h in headers:
            if h in probe_response.headers:
                print(h, "found")
            else:
                print(h, "not found")
    
    except requests.RequestException as e:
        print("Connection failed")

   

def port_scan():
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


def authenticate():
    username = input("Username: ")
    password = getpass("Password: ")

    client_socket.sendall(
        f"AUTH|{username}|{password}".encode()
    )

    response = client_socket.recv(1024).decode().strip()

    if response == "OTP_REQUIRED":
        otp = input("OTP: ")

        client_socket.sendall(
            f"OTP|{otp}".encode()
        )

        response = client_socket.recv(1024).decode().strip()

    if response == "ACCESS_GRANTED":
        return True
    elif response == "ACCESS_DENIED":
        return False
    elif response.startswith("ERROR|"):
        print(response)
    else:
        print("Unexpected server response")


try:
    client_socket.connect((HOST, PORT))

    if authenticate():
        print("Authenticated!")
        while True:
            menu = client_socket.recv(1024).decode().strip()
            if not menu:
                break
            print(menu)

            choice = input("> ").strip()
            client_socket.sendall(choice.encode())

            # if choice == "0":
            #     for _ in range(3):
            #         prompt = client_socket.recv(1024).decode().strip()
            #         if not prompt:
            #             break
            #         value = input(f"{prompt} ").strip()
            #         client_socket.sendall(value.encode())

            response = client_socket.recv(1024).decode().strip()
            print(response)
            if response.casefold() == "exit":
                break
            if choice == "0" and response == "PORTSCAN":
                port_scan()
            elif choice == "1" and response == "HTTPSCAN":
                http_scan()
            elif choice == "2" and response == "PCAPSCAN":
                response = client_socket.recv(1024).decode().strip()
                print(response)
            
    
finally:
    client_socket.close()