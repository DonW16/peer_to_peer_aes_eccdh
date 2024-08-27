from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import hash_secret_raw, Type
import os 
import socket
import threading
import time

class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []

    def connect(self, peer_host, peer_port):
        connection = socket.create_connection((peer_host, peer_port))

        self.connections.append(connection)
        print(f"Connected to {peer_host}:{peer_port} \n")

    def listen(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port} \n")

        while True:
            connection, address = self.socket.accept()
            self.connections.append(connection)
            print(f"Accepted connection from {address[0]}:{address[1]} \n")
            threading.Thread(target=self.handle_client, args=(connection, address)).start()

    def send_data(self, data):
        for connection in self.connections:
            try:
                connection.sendall(data)
            except socket.error as e:
                print(f"Failed to send data. Error: {e}")
                self.connections.remove(connection)

    def handle_client(self, connection, address):
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                print(f"Received data from {address}: {data} \n")
                return data  # Return the received data
            except socket.error:
                break

        print(f"Connection from {address} closed. \n")
        self.connections.remove(connection)
        connection.close()
        return None  # Return None if the connection is closed or an error occurs

    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

class Generate_Keys:
    # Keys are generated using the Elliptic Curve Diffie-Hellman (ECDH) algorithm and are ephemeral, new keys are generated for each session.
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.iv = None
        self.salt = None

    def derive_key_argon2(self, shared_secret, salt):
        self.derive_key = hash_secret_raw(
            secret=shared_secret,
            salt=salt,
            time_cost=32,           # Number of iterations
            memory_cost=204800,     # Memory cost in KiB (200 MiB)
            parallelism=8,          # Number of parallel threads
            hash_len=32,            # Length of the derived key in bytes (32 bytes for AES-256)
            type=Type.ID            # Use Argon2id for the key derivation
        )
        return self.derive_key

    def derive_shared_key(self, peer_public_key, salt):
        # Derive the shared secret using peer's public key
        self.shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.salt = salt
        return self.derive_key_argon2(self.shared_key, self.salt)

    # def verify_shared_key(self, peer_shared_key):
    #     if self.shared_key == peer_shared_key:
    #         print(f"Shared key: {peer_shared_key.hex()} is the same! ")
    #         return self.shared_key == peer_shared_key
    #     else:
    #         print(f"Shared key: {peer_shared_key.hex()} is not {self.shared_key.hex()}! ")
    
    def encrypt_message(self, message, derive_key):
        iv = os.urandom(16)
        self.cipher = Cipher(algorithms.AES256(derive_key), modes.CFB(iv))
        self.encryptor = self.cipher.encryptor()
        message = message.encode('utf-8')
        self.ciphertext = self.encryptor.update(message) + self.encryptor.finalize()
        return self.ciphertext, iv
    
    def decrypt_message(self, ciphertext, derive_key):
        
        self.cipher = Cipher(algorithms.AES256(derive_key), modes.CFB(iv))
        self.decryptor = self.cipher.decryptor()
        self.plaintext = self.decryptor.update(ciphertext) + self.decryptor.finalize()
        return self.plaintext.decode()
    
    def get_public_key_bytes(self):
        # Serialize the public key to bytes for transmission
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def load_public_key(public_key_bytes):
        # Deserialize public key from bytes
        return serialization.load_pem_public_key(public_key_bytes)
    
# Example usage:
if __name__ == "__main__":

    # Node 1 generates keys
    node1_keys = Generate_Keys()
    node1_public_key_bytes = node1_keys.get_public_key_bytes()

    # Node 2 generates keys 
    node2_keys = Generate_Keys()
    node2_public_key_bytes = node2_keys.get_public_key_bytes()

    # Exchange public keys
    node1_peer_public_key = Generate_Keys.load_public_key(node2_public_key_bytes)
    node2_peer_public_key = Generate_Keys.load_public_key(node1_public_key_bytes)

    # Generate shared salt
    shared_salt = os.urandom(32)

    # Derive shared keys
    node1_shared_key = node1_keys.derive_shared_key(node1_peer_public_key, shared_salt)
    node2_shared_key = node2_keys.derive_shared_key(node2_peer_public_key, shared_salt)

    # node1_keys.verify_shared_key(node2_shared_key)
    # node2_keys.verify_shared_key(node1_shared_key)

    # # Verify that the shared keys are the same
    # if node1_shared_key == node2_shared_key:
    #     print(f"Shared node 1 {node1_shared_key} and Shared node 2 {node2_shared_key} keys are the same!")
    # else:
    #     print(f"Shared node 1 {node1_shared_key} and Shared node 2 {node2_shared_key} keys are not the same!")

    node1 = Peer("127.0.0.1", 8000)
    node1.start()

    node2 = Peer("127.0.0.1", 8001)
    node2.start()

    # Check if nodes are listening
    while True:
        if node1.socket.fileno() != -1 and node2.socket.fileno() != -1:
            print("Nodes are listening \n")
            break
        else:
            time.sleep(1)

    # Node 1 connects to Node 2
    node1.connect(node2.host, node2.port)

    # Take user input for message
    message = input("Enter a message: ")

    # Node 1 encrypts the message using the shared key
    ciphertext, iv = node1_keys.encrypt_message(message, node1_shared_key)
    print(f"Node1: Ciphertext: {ciphertext.hex()}")
    print(f"Node1: IV: {iv.hex()}")

    # Node 1 sends the encrypted message to Node 2
    node1.send_data(ciphertext)

    # Node 2 receives the encrypted message
    ciphertext = node2.handle_client(node2.connections[0], (node1.host, node1.port))
    plaintext = node2_keys.decrypt_message(ciphertext, node2_shared_key)
    print(f"Node2: Ciphertext: {ciphertext.hex()}")
    print(f"Node2: IV: {iv.hex()}")
    print(f"Node2: Plaintext: {plaintext}")
