from aiohttp import web
import socketio

socket = socketio.AsyncServer()

app = web.Application()

socket.attach(app)
async def index(request):
    return

web.Response(text='Hello World', content_type='text/html')

username = ""

@socket.event
async def msg(socket_id, data): 
    content = ""

    if "|" not in data.decode():
        await socket.disconnect(socket_id)
    else:
        command, content = data.decode().split("|", 1)

        if command == "HELLO":
            username = content
            print("Username:", username)
            await socket.emit("msg", ("OK|Hello " + username).encode())
                
        elif command == "MSG":
            print(username + " says:", content)
            await socket.emit("msg", ("OK|Message received from " + username).encode())

        elif command == "EXIT":
            await socket.emit("msg", "OK|Goodbye".encode())
            await socket.disconnect(socket_id)

        else:
            await socket.emit("msg", "ERROR|Unknown command".encode())

app.router.add_get('/', index)

web.run_app(app)