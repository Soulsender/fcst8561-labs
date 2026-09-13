from aiohttp import web

import socketio

socket = socketio.AsyncServer()

app = web.Application()

socket.attach(app)
async def index(request):
    return

web.Response(text='Hello World', content_type='text/html')

@socket.on('message')
def print_message(socket_id, data):
    print("Socket ID:", socket_id)
    print("Data:", data)

app.router.add_get('/', index)

web.run_app(app)