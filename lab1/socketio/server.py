from aiohttp import web
import socketio

socket = socketio.AsyncServer()

app = web.Application()

socket.attach(app)
async def index(request):
    return

web.Response(text='Hello World', content_type='text/html')

@socket.event
def msg(socket_id, data):
    command, content = data.split("|", 1)
    if command == "HELLO":
        if content == "":
            socket.emit(
                "ERROR|Username required".encode()
            )
        else:
            username = content
            print("Username:", username)
            socket.emit(
                "OK|Hello ".encode() + username.encode()
            )

app.router.add_get('/', index)

web.run_app(app)