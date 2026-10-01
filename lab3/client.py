import socket

HOST = "127.0.0.1"
PORT = 12346

username = input("Username: ")
password = input("Password: ")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

auth_message = f"AUTH|{username}|{password}"
client_socket.sendall(auth_message.encode())

response = client_socket.recv(1024).decode().strip()

if response == "OTP_REQUIRED":
    otp = input("OTP: ")

    otp_message = f"OTP|{otp}"
    client_socket.sendall(otp_message.encode())

    response = client_socket.recv(1024).decode().strip()

if response == "ACCESS_GRANTED":
    print("Access granted")
elif response == "ACCESS_DENIED":
    print("Access denied")
elif response.startswith("ERROR|"):
    print(response)
else:
    print("Unexpected server response")

client_socket.close()
