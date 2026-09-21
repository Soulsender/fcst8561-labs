import socketio

socket = socketio.Client()

@socket.event
def connect():
    print("Connection established")

@socket.event
def disconnect():
    print("Disconnected")

socket.connect("http://localhost:8080")

while True:
    message = input("Send: ")
    socket.emit("msg", message.encode())

    @socket.event
    def msg(socket_id, data):
        print(data.decode())

socket.wait()


