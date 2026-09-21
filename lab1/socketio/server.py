from aiohttp import web
import socketio

socket = socketio.AsyncServer()

app = web.Application()

socket.attach(app)
async def index(request):
    return

web.Response(text='Hello World', content_type='text/html')

username = "jasper"

@socket.event
async def msg(socket_id, data):
    command, content = data.decode().split("|", 1)

    if command == "HELLO":
        if content == "":
            socket.emit("msg", "ERROR|Username required".encode())
        else:
            username = content
            print("Username:", username)
            socket.emit("msg", ("OK|Hello " + username).encode())
            
    elif command == "MSG":
        if username is None:
            socket.emit("msg", "ERROR|HELLO required first".encode())
        elif content == "":
            socket.emit("ERROR|Message cannot be empty".decode())
        else:
            print(username + " says:", content)
            socket.emit("msg", "OK|Message received from " + username.encode())

    elif command == "EXIT":
        socket.emit("msg", "OK|Goodbye".encode())
        socket.disconnect()

    else:
        socket.emit("msg", "ERROR|Unknown command".encode())

app.router.add_get('/', index)

web.run_app(app)