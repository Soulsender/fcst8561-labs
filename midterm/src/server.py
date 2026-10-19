import socket, hashlib, pyotp

HOST = "127.0.0.1"
PORT = 4444

users = {
    "jasper": {
        "password_hash": hashlib.sha256(
            "password".encode()
        ).hexdigest(),
        "totp_secret": "PQE6UTKFIXGL"
    }
}

def authenticate(client_socket):
    message = client_socket.recv(1024).decode().strip()
    parts = message.split("|")

    if len(parts) != 3 or parts[0] != "AUTH":
        client_socket.sendall(b"ERROR|Invalid authentication request")
        return False

    username = parts[1]
    password = parts[2]

    if username not in users:
        client_socket.sendall(b"ACCESS_DENIED")
        return False

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash != users[username]["password_hash"]:
        client_socket.sendall(b"ACCESS_DENIED")
        return False

    client_socket.sendall(b"OTP_REQUIRED")

    message = client_socket.recv(1024).decode().strip()

    parts = message.split("|")

    if len(parts) != 2 or parts[0] != "OTP":
        client_socket.sendall(b"ERROR|Invalid OTP request")
        return False

    otp = parts[1]

    totp = pyotp.TOTP(users[username]["totp_secret"])

    if totp.verify(otp):
        client_socket.sendall(b"ACCESS_GRANTED")
        return True
    else:
        client_socket.sendall(b"ACCESS_DENIED")
        return False

def menu(client_socket):
    client_socket.sendall(
        b"\n\nChoose an operation:\n"
        b"[0] - Port scan (client side)\n"
        b"[1] - HTTP scan (client side)\n"
        b"[2] - PCAP scan (server side)\n"
        b"Type exit to quit.\n"
    )
    message = client_socket.recv(1024).decode().strip()
    if not message:
        return False

    if message == "0":
        print("Port scan selected")
        client_socket.sendall(b"PORTSCAN")
    elif message == "1":
        print("HTTP scan selected")
        client_socket.sendall(b"HTTPSCAN")
    elif message == "2":
        print("PCAP scan selected")
        client_socket.sendall(b"PCAPSCAN")
    elif message == "exit":
        print("Exiting...")
        client_socket.sendall(b"EXIT")
        client_socket.close()
    else:
        client_socket.sendall(b"ERROR|Invalid option")
    return True

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"Server listening on {HOST}:{PORT}")

while True:
    client_socket, address = server_socket.accept()
    print("Client received")

    try:
        if authenticate(client_socket):
            print("User successfully authenticated")
            while menu(client_socket):
                pass

    except Exception as error:
        client_socket.sendall(
            f"ERROR|{error}".encode()
        )
    finally:
        client_socket.close()
