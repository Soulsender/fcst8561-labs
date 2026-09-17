import socketio

socket = socketio.Client()

@socket.event
def connect():
    print("Connection established")

@socket.event
def disconnect():
    print("Disconnected")

@socket.event
def msg(data):
    print(data)

socket.connect("http://localhost:8080")

message = input("Send: ")
socket.emit("msg", message)

socket.wait()