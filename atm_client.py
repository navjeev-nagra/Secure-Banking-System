import socket


def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 9237))

    # Simulate user login
    username = input("Enter username: ")
    password = input("Enter password: ")
    client.send((username + '\n').encode('utf-8'))  # Append '\n' as delimiter
    client.send((password + '\n').encode('utf-8'))  # Append '\n' as delimiter
    response = client.recv(4096)
    print(f"Server response: {response.decode('utf-8')}")


    # Simulate user actions
    while True:
        action = input("Enter action (BALANCE, DEPOSIT <amount>, WITHDRAW <amount>, or QUIT): ")
        client.send(action.encode('utf-8'))
        if action == "QUIT":
            break
        response = client.recv(4096)
        print(f"Server response: {response.decode('utf-8')}")

    client.close()


if __name__ == "__main__":
    connect_to_server()