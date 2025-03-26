from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)
print("Server is listening...")

# Generate RSA key pair
server_key = RSA.generate(2048)

# Function to handle client connection
def handle_client(client_socket):
    try:
        # Send server's public key to the client
        client_socket.send(server_key.publickey().export_key(format='PEM'))

        # Receive client's public key
        client_public_key = RSA.import_key(client_socket.recv(2048))

        # Generate AES key and encrypt it with the client's public key
        aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        client_socket.send(encrypted_aes_key)

        # Function to encrypt message
        def encrypt_message(key, message):
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
            return cipher.iv + ciphertext

        # Function to decrypt message
        def decrypt_message(key, encrypted_message):
            iv = encrypted_message[:AES.block_size]
            ciphertext = encrypted_message[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted_message.decode()

        # Receive and send messages
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("Client disconnected.")
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print("Received:", decrypted_message)

            # Echo the message back to the client
            response = f"Server received: {decrypted_message}"
            encrypted_response = encrypt_message(aes_key, response)
            client_socket.send(encrypted_response)

    except Exception as e:
        print("Error handling client:", e)
    finally:
        client_socket.close()

# Accept client connections
while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()