import socket
import ssl
import threading

server_address = ('localhost', 12345)

clients = []

def handle_client(client_socket):
    clients.append(client_socket)
    print("Đã kết nối với:", client_socket.getpeername())
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print("Nhận:", data.decode())

            for client in clients:
                if client != client_socket:
                    try:
                        client.send(data)
                    except:
                        clients.remove(client)
    except:
        clients.remove(client_socket)
    finally:
        print("Đã ngắt kết nối:", client_socket.getpeername())
        clients.remove(client_socket)
        client_socket.close()

cerver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cerver_socket.bind(server_address)
cerver_socket.listen(5)

print("Server đang chờ kết nối...")

while True:
    client_socket, client_address = cerver_socket.accept()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
