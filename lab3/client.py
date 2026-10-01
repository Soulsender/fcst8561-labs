import socket
# from getpass import getpass

HOST = "127.0.0.1"
PORT = 12346

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client_socket.connect((HOST, PORT))

    username = input("Username: ")
    password = input("Password: ")

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
        print("ACCESS_GRANTED")
    elif response == "ACCESS_DENIED":
        print("ACCESS_DENIED")
    elif response.startswith("ERROR|"):
        print(response)
    else:
        print("Unexpected server response")

finally:
    client_socket.close()