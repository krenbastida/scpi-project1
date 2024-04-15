from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, join_room, leave_room, send, emit
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
cont = 0

@app.route("/", methods=["GET", "POST"])
def prime():
    return redirect(url_for('login')) #Nuevas lineas para no necesitar ajustar la URL en el navegador
@app.route("/login", methods=["GET", "POST"])

def login():
    if request.method == "POST": #Si POST toma el nombre del usuario y mándalo a la página del chat
        username = request.form['username']
        usuarios[username] = {}
        publica, privada = generate_keys_RSA(username) ################################### AQUI!!!!! AQUI MERO SE GENERAN LAS LLAVES PUB Y PRIV (se guardan)
        password = request.form['password']
        global cont
        cont = cont + 1
        print(cont)
        if(cont==2): #Ya que están los dos, se genera el secreto
            secreto = generate_key_PBKDF(str(password),urandom(16))  ############AQUI!!!!! AQUI MERO SE GENERA EL SECRETO (LA SIMETRICA)
            cipher = PKCS1_OAEP.new(publica) #################### AQUI!!!! AQUI MERO SE CIFRA LA SIMETRICA CON LA ASIMETRICA
            secreto = cipher.encrypt(str(secreto).encode())
            #Con esta declaracion de diccionarios de cada usuario, nos aseguramos que los 2 tienen el secreto para cifrar mensajes, se actualiza
            #el valor del secreto usando el password del último usuario en ingresar.
            usuarios[username] = {
                "secreto": secreto,
                "publica": publica.export_key(),
                "privada": privada
            }
        #     #binascii.hexlify(encrypted_message).decode()
        else:
            print("NO")
            usuarios[username] = {
                "secreto": None,
                "publica": publica.export_key(),
                "privada": privada
            }
        return redirect(url_for('chat', name=username))
    return render_template('login.html') #Si GET mándale la plantilla login

#Llaves para enviar secreto
def generate_keys_RSA(username):
    key = RSA.generate(2048)  # Genera una clave RSA de 2048 bits
    private_key = key.export_key(pkcs=8)
    public_key = key.publickey().export_key()
    # Guardar la clave pública
    with open("public_"+username+".pem", "wb") as pu_file:
        pu_file.write(public_key)
    with open("private_"+username+".pem", "wb") as pr_file:
        pr_file.write(private_key)
    return key.publickey(),private_key

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
        users[username] = room
        join_room(room)
        send(f"{username} se unió al chat", to=room)
        #El servidor envía llaves al cliente correspondiente para que las almacene
        #El cliente entiende este envío con el mensaje "keys"
        publica = str(usuarios[username]["publica"])
        privada = str(usuarios[username]["privada"])
        publica = publica.replace('\\n','')
        privada = privada.replace('\\n','')
        print(privada)
        d = {
                "publica": publica,
                "privada": privada
            }
        emit('keys', d) 

#Cuando recibe la respuesta de recibido de llaves, se procede a compartir el secreto...
@socketio.on('OK')
def on_OK():
    print("\n OK")
    for clave in usuarios.keys(): #Se recorre el diccionario hasta encontrar al usuario que tiene el secreto
        if(usuarios[clave]["secreto"] != None):
            print(usuarios[clave]["secreto"])
            emit('secret',usuarios[clave]["secreto"])#Se emite en caso de encontrarse

@socketio.on('gime_public')
def on_gime_public(data): #Recibe el usuario que pide la publica
    for clave in usuarios.keys(): #Se recorre el diccionario hasta encontrar al usuario del que se necesita la publica
        if(clave != data): #El que no es igual al que pide
            pk = str(usuarios[clave]["publica"])
            print("Soy "+clave+" y te daré mi pública: ")
            ##Procesamos la llave para que no tenga problemas de formato
            pk = pk.replace('\\n','') #Se quitan los saltos de línea
            print(pk)
            emit('here_you_have', pk) #Se emite en caso de encontrarse

@socketio.on('share_secret')
def on_share_secret(data): #Recibe el secreto cifrado
    print("\n Recibi el secreto cifrado, ahora lo enviaré a todos!!!")
    print(data)
    emit('shared',data)#Se comparte el secreto cifrado con todos (solo podrá verlo el que compartió su pública)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = users[username]
    leave_room(room)
    del users[username]
    send(f"{username} ha salido del chat", to=room)

# @socketio.on('symmetric_key')
# def on_message(data):
#     #username = data['username'] #Alice
#     sender = users[username]
#     message = data['']
#     publica = usuarios[username]["publica"]
#     send(f"{username}: {message}  {publica}", to=room)

@socketio.on('message')
def on_message(data):
    username = data['username']
    room = users[username]
    message = data['message']
    send(f"{username}: {message}", to=room) #usuarios[username] envía los datos del usuario

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

#Cifrado de mensaje con AES usando el secreto y firma

def encrypt_message(key: bytes, plaintext: str, hash: bytes, signature: bytes) -> dict:
    """Cifra un mensaje usando AES con el modo CBC."""
    iv = urandom(16)  # Vector de inicializacion
    key = usuarios["Alice"].secreto.encode(); #Los 2 usuarios ya tienen el secreto, lo obtenemos de uno de ellos
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) #Definir algoritmo de cifrado
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext.encode(), 16)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return {
        "iv": urlsafe_b64encode(iv).decode(),
        "ciphertext": urlsafe_b64encode(ciphertext).decode(),
        "hash": urlsafe_b64encode(hash).decode(),
        "signature": urlsafe_b64encode(signature).decode()
    }

def pad(data: bytes, block_size: int) -> bytes:
    """Agrega padding al mensaje para que sea múltiplo del tamaño de bloque."""
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

def decrypt_message(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    """Descifra un mensaje cifrado usando AES con el modo CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext, 16)
    return plaintext.decode()

def unpad(padded_data: bytes, block_size: int) -> bytes:
    """Elimina el padding del mensaje."""
    padding_length = padded_data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    return padded_data[:-padding_length]

def verify_signature(public_key, signature, message_hash):
    """Verifica la firma del mensaje usando la llave pública RSA."""
    try:
        public_key.verify(
            signature,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

## Para poder mandar sin que se vea en pantalla, hay que definir nuevas funciones @socket.on('EVENTO')
## Para que haga ciertas acciones en presencia de un evento generado por los componentes WEB en chat.html

## Pensar en qué parte se hace el cifrado y descifrado

##Descargar Node.js, reiniciar y hacer este comando "npm install crypto-js"

'''def encrypt_with_public_key(message: bytes, public_key: bytes) -> bytes:
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


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

def encrypt_with_public_key(message: bytes, public_key: bytes) -> bytes:
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)'''

if __name__ == '__main__':
    socketio.run(app, host='localhost', port=81, debug=True)
