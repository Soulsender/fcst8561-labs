import socketio

sio = socketio.Client()

@sio.event
def connect():
    print("Connection established")

@sio.event
def disconnect():
    print("Disconnected")

sio.connect("http://localhost:8080")
sio.emit("message", {"data": "my_data"})
sio.wait()