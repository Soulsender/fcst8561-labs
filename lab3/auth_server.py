import socket
import hashlib
import pyotp

HOST = "127.0.0.1"
PORT = 12346

users = {
    "alice": {
        "password_hash": hashlib.sha256(
            "Cyber123!".encode()
        ).hexdigest(),
        "totp_secret": "PQE6UTKFIXGL"
    }
}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(client_socket):
    message = client_socket.recv(1024).decode().strip()

    parts = message.split("|")

    if len(parts) != 3 or parts[0] != "AUTH":
        client_socket.sendall(b"ERROR|Invalid authentication request")
        return

    username = parts[1]
    password = parts[2]

    if username not in users:
        client_socket.sendall(b"ACCESS_DENIED")
        return

    password_hash = hash_password(password)

    if password_hash != users[username]["password_hash"]:
        client_socket.sendall(b"ACCESS_DENIED")
        return

    client_socket.sendall(b"OTP_REQUIRED")

    message = client_socket.recv(1024).decode().strip()

    parts = message.split("|")

    if len(parts) != 2 or parts[0] != "OTP":
        client_socket.sendall(b"ERROR|Invalid OTP request")
        return

    otp = parts[1]

    totp = pyotp.TOTP(users[username]["totp_secret"])

    if totp.verify(otp):
        client_socket.sendall(b"ACCESS_GRANTED")
        print("OTP client authenticated")
    else:
        client_socket.sendall(b"ACCESS_DENIED")


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"Server listening on {HOST}:{PORT}")

while True:
    client_socket, address = server_socket.accept()
    print("Client received")

    try:
        authenticate(client_socket)
    except Exception as error:
        client_socket.sendall(
            f"ERROR|{error}".encode()
        )
    finally:
        client_socket.close()
