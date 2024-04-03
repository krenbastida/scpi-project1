from flask import Flask, render_template, request, redirect, url_for
#SocketIO para la comunicación bidireccional con WebSockets
from flask_socketio import SocketIO, join_room, leave_room, send

#import ssl #NEW

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
#Instancia del SocketIO
socketio = SocketIO(app)


# Configuración SSL
#certh_path = 'cert.pem' #NEW
#key_path = 'key.pem' #NEW
#context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) #NEW
#context.load_cert_chain(certh_path, key_path) #OJO, FALTA CONSEGUIRLOS #NEW
#socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading', ssl_context=context) #NEW. OJO HAY QUE REEMPLAZAR POR LÍNEA 10

#Diccionario para almacenar los usuarios que se van registrando
users = {}  

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST": #Si POST toma el nombre del usuario y mándalo a la página del chat
        username = request.form['username']
        return redirect(url_for('chat', name=username))
    return render_template('login.html') #Si GET mándale la plantilla login

@app.route('/chat/<name>', methods=["GET", "POST"])
#Esta función renderiza la pantalla del chat.
def chat(name):
    return render_template('chat.html', name=name)

@socketio.on('join')
#data es un diccionario para encontrar el username y room que se envía del cliente al servidor
def on_join(data):
    username = data['username'] 
    room = data['room']
    #Se une a una sala para que pueda interactuar con los otros usuarios
    join_room(room)
    #Se registra que cierto usuario está en cierto room
    users[username] = room
    send(f"{username} se unió al chat", to=room)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = users[username]
    leave_room(room)
    del users[username]
    send(f"{username} ha salido del chat", to=room)

@socketio.on('message')
def on_message(data):
    username = data['username']
    room = users[username]
    message = data['message']
    send(f"{username}: {message}", to=room)

if __name__ == '__main__':
    socketio.run(app, host='localhost', port=81, debug=True)
    #socketio.run(app, host='localhost', port=81, debug=True, ssl_context=context) #NEW