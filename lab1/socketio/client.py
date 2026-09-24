import socketio

socket = socketio.Client()
connected = True

@socket.event
def connect():
    print("Connection established")

@socket.event
def disconnect():
    print("Disconnected")

@socket.event
def msg(data):
    print(data.decode())

socket.connect("http://localhost:8080")

while connected:
    message = input("Send: ")

    if message == "EXIT":
        socket.emit("msg", message.encode())
        socket.wait()
        connected = False
    else:
        socket.emit("msg", message.encode())



