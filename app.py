from flask import Flask, render_template, request, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
import websockets

#Python -m flask run (para ejecutar proyecto desde consola)

app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST": #Si POST toma el nombre del usuario y mándalo a la página del chat
        username = request.form['username']
        publica = generate_keys_RSA(username) ################################### AQUI!!!!! AQUI MERO SE GENERAN LAS LLAVES PUB Y PRIV (se guardan)
        password = request.form['password']
        secreto = generate_key_PBKDF(str(password),urandom(16))  ############AQUI!!!!! AQUI MERO SE GENERA EL SECRETO (LA SIMETRICA)

        cipher = PKCS1_OAEP.new(publica) #################### AQUI!!!! AQUI MERO SE CIFRA LA SIMETRICA CON LA ASIMETRICA
        secreto = cipher.encrypt("hola".encode())
        print(secreto)
        #binascii.hexlify(encrypted_message).decode()
        return redirect(url_for('chat', name=username))
    return render_template('login.html') #Si GET mándale la plantilla login

@app.route('/chat/<name>', methods=["GET", "POST"])
#Esta función renderiza la pantalla del chat.
def chat(name):
    return render_template('chat.html', name=name)

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

if __name__ == '__main__':
    app.run(host='localhost', port=81, debug=True)

'''
# Guardar la clave privada
    with open("private.pem", "wb") as pr_file:
        pr_file.write(private_key)

    # Guardar la clave pública
    with open("public.pem", "wb") as pu_file:
        pu_file.write(public_key)
'''