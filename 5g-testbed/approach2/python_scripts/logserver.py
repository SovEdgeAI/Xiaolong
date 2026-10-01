import socket

def start_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")

        while True:
            client_socket, _ = server_socket.accept()
            print("Client connected")

            with client_socket:
                data = client_socket.recv(1024).decode('utf-8')
                print("Received data:", data)

                # Process the received data here as needed
                # For demonstration, simply echo back "1"
                response = "1"
                client_socket.sendall(response.encode('utf-8'))
                print("Response sent")

if __name__ == "__main__":
    HOST = '0.0.0.0'  # Listen on all available interfaces
    PORT = 7000
    start_server(HOST, PORT)
