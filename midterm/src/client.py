import ipaddress, socket, nmap, requests
from getpass import getpass

HOST = "127.0.0.1"
PORT = 4444

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def http_scan():
    base_url = input("Enter URL of target: ").strip()
    if not base_url:
        print("A target URL is required.")
        return

    headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Powered-By", "Server"]

    try:
        probe_response = requests.get(base_url, timeout=5)

        print(f"Server reported: {probe_response.status_code}")

        print("Testing Headers...")
        for h in headers:
            if h in probe_response.headers:
                print(h, "found")
            else:
                print(h, "not found")
    
    except requests.RequestException as error:
        print(f"HTTP scan failed: {error}")

   

def port_scan():
    target = input("Enter target: ").strip()
    if not target:
        print("A target is required.")
        return

    try:
        start_port = int(input("Enter start port: ").strip())
        end_port = int(input("Enter end port: ").strip())
    except ValueError:
        print("Ports must be integers.")
        return

    open_ports = []

    def validate_port(port: int):
        return 1 <= port <= 65535

    if not (validate_port(start_port) and validate_port(end_port) and start_port <= end_port):
        print("Invalid port range. Use ports from 1 to 65535 with start <= end.")
        return

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, f"{start_port}-{end_port}")
    except (nmap.PortScannerError, OSError) as error:
        print(f"Port scan failed: {error}")
        return

    print(f"Scan results for {target}")

    hosts = scanner.all_hosts()
    if not hosts:
        print("No scan results were returned for that target.")
        return

    for host in hosts:
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()

            for port in sorted(ports):
                port_info = scanner[host][protocol][port]
                service = port_info.get("name")
                if port_info.get("state") == "open":
                    print(f"Port {port} is OPEN using {service}")
                    open_ports.append(port)

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
        while True:
            menu = client_socket.recv(1024).decode().strip()
            if not menu:
                break
            print(menu)

            choice = input("> ").strip()
            is_exit = choice.casefold() == "exit"
            client_socket.sendall(b"exit" if is_exit else choice.encode())

            # if choice == "0":
            #     for _ in range(3):
            #         prompt = client_socket.recv(1024).decode().strip()
            #         if not prompt:
            #             break
            #         value = input(f"{prompt} ").strip()
            #         client_socket.sendall(value.encode())

            response = client_socket.recv(1024).decode().strip()
            if not response:
                break
            print(response)
            if is_exit or response.casefold() == "exit":
                break
            if choice == "0" and response == "PORTSCAN":
                port_scan()
            elif choice == "1" and response == "HTTPSCAN":
                http_scan()
            elif choice == "2" and response == "PCAPSCAN":
                response = client_socket.recv(1024).decode().strip()
                print(response)
            
    
except (OSError, EOFError) as error:
    print(f"Client connection/input error: {error}")
except KeyboardInterrupt:
    print("Client stopped.")
finally:
    try:
        client_socket.close()
    except OSError:
        pass