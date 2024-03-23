import socket
import threading
def handle_client(client_socket):
    try:
        # Receive username
        username = ""
        while True:
            char = client_socket.recv(1).decode('utf-8')
            if char == '\n':
                break
            username += char
        print(f"Username received: {username}")

        # Receive password
        password = ""
        while True:
            char = client_socket.recv(1).decode('utf-8')
            if char == '\n':
                break
            password += char
        print(f"Password received: {password}")

        # Send a response to acknowledge login
        client_socket.send(b"Logged in successfully")

        while True:
            # Process commands as before
            command = client_socket.recv(1024).decode('utf-8').split()
            if not command or command[0] == "QUIT":
                break  # Quit if no command or QUIT command received

            if command[0] == "BALANCE":
                client_socket.send(b"Balance feature not yet implemented")
            elif command[0] == "DEPOSIT":
                client_socket.send(b"Deposit feature not yet implemented")
            elif command[0] == "WITHDRAW":
                client_socket.send(b"Withdrawal feature not yet implemented")
            else:
                client_socket.send(b"Invalid command")
    finally:
        client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9237))
    server.listen(5)
    print("Server listening on localhost")
    try:
        while True:
            client_sock, address = server.accept()
            print(f"Accepted connection from {address}")
            client_handler = threading.Thread(target=handle_client, args=(client_sock,))
            client_handler.start()
    finally:
        server.close()


if __name__ == "__main__":
    start_server()