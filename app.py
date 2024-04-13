from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
import websockets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

# Diccionario para almacenar los usuarios que se van registrando
users = {}
usuarios = {} #Para no tener conflico con el archivo JSON que se crea automáticamente


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST": #Si POST toma el nombre del usuario y mándalo a la página del chat
        username = request.form['username']

        usuarios[username] = {}
        publica = generate_keys_RSA(username) ################################### AQUI!!!!! AQUI MERO SE GENERAN LAS LLAVES PUB Y PRIV (se guardan)
        password = request.form['password']
        num_usuarios = len(users)
        print(num_usuarios)
        if(num_usuarios==2): #Ya que están los dos, se genera el secreto
            secreto = generate_key_PBKDF(str(password),urandom(16))  ############AQUI!!!!! AQUI MERO SE GENERA EL SECRETO (LA SIMETRICA)
            cipher = PKCS1_OAEP.new(publica) #################### AQUI!!!! AQUI MERO SE CIFRA LA SIMETRICA CON LA ASIMETRICA
            secreto = cipher.encrypt(str(secreto).encode())
            usuarios[username] = {
                "secreto": secreto,
                "publica": publica.export_key() 
            }
            #binascii.hexlify(encrypted_message).decode()
        else:
            print("NO")
            usuarios[username] = {
                "secreto": None,
                "publica": publica.export_key()
            }
        #print(usuarios)
        #print(users)

        return redirect(url_for('chat', name=username))
    return render_template('login.html') #Si GET mándale la plantilla login

@app.route('/chat/<name>', methods=["GET", "POST"])
#Esta función renderiza la pantalla del chat.
def chat(name):
    if(name == "Alice" or name=="Bob"):
        return render_template('chat.html', name=name)
    else:
        return redirect(url_for('login'))

@socketio.on('join')
def on_join(data):
    username = data['username']
    
    if(username=="Alice" or username=="Bob"):
        room = data['room']
        join_room(room)
        users[username] = room
        send(f"{username} se unió al chat", to=room)
    else:
        send(f"{username} intentó unirse")


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
    publica = usuarios[username]["publica"]
    send(f"{username}: {message}  {publica}", to=room)

def generate_keys_RSA(username):
    key = RSA.generate(2048)  # Genera una clave RSA de 2048 bits
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_"+username+".pem", "wb") as pr_file:
        pr_file.write(private_key)

    # Guardar la clave pública
    with open("public_"+username+".pem", "wb") as pu_file:
        pu_file.write(public_key)
    return key.publickey()

def generate_key_PBKDF(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32) -> bytes:
    """Genera una llave a partir de una contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

## Para poder mandar sin que se vea en pantalla, hay que definir nuevas funciones @socket.on('EVENTO')
## Para que haga ciertas acciones en presencia de un evento generado por los componentes WEB en chat.html

## Pensar en qué parte se hace el cifrado y descifrado

'''def encrypt_with_public_key(message: bytes, public_key: bytes) -> bytes:
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)'''


def generate_keys_RSA(username):
    key = RSA.generate(2048)  # Genera una clave RSA de 2048 bits
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_"+username+".pem", "wb") as pr_file:
        pr_file.write(private_key)

    # Guardar la clave pública
    with open("public_"+username+".pem", "wb") as pu_file:
        pu_file.write(public_key)
    return key.publickey()

def generate_key_PBKDF(password: str, salt: bytes, iterations: int = 100000, key_length: int = 32) -> bytes:
    """Genera una llave a partir de una contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

'''def encrypt_with_public_key(message: bytes, public_key: bytes) -> bytes:
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)'''

if _name_ == '_main_':
    socketio.run(app, host='localhost', port=81, debug=True)
