import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

user_credentials = {}
user_balances = {}

def handle_client(conn, address):
    logging.info(f"Connection from: {address}")
    try:
        data = conn.recv(4096).decode()
        parts = data.split('||')
        if len(parts) < 2:
            logging.error("Invalid message format received.")
            conn.send(b"Invalid message format.")
            return

        action, username = parts[0], parts[1]
        if action == "register":
            password = parts[2]
            handle_registration(conn, username, password)
            user_balances[username] = 0
        elif action == "login":
            password = parts[2]
            handle_login(conn, username, password)
        elif action == "deposit":
            amount = float(parts[2])
            success, message = handle_deposit(username, amount)
            conn.send(message.encode())
        elif action == "withdraw":
            amount = float(parts[2])
            success, message = handle_withdrawal(username, amount)
            conn.send(message.encode())
        elif action == "balance":
            success, message = handle_balance_inquiry(username)
            conn.send(message.encode())
        else:
            logging.warning(f"Unknown action received: {action}")
    finally:
        conn.close()
        logging.info(f"Connection with {address} closed.")

def handle_registration(conn, username, password):
    if username in user_credentials:
        conn.send(b"Username already exists.")
        logging.warning(f"Registration attempt with existing username: {username}")
    else:
        user_credentials[username] = password
        conn.send(b"Registration successful.")
        logging.info(f"New user registered: {username}")

def handle_login(conn, username, password):
    if username in user_credentials and user_credentials[username] == password:
        conn.send(b"Login successful.")
        logging.info(f"User logged in: {username}")
    else:
        conn.send(b"Login failed.")
        logging.warning(f"Failed login attempt for username: {username}")

def handle_deposit(username, amount):
    if username in user_balances:
        user_balances[username] += amount
        return True, "Deposit successful."
    return False, "User not found."

def handle_withdrawal(username, amount):
    if username in user_balances and user_balances[username] >= amount:
        user_balances[username] -= amount
        return True, "Withdrawal successful."
    return False, "Insufficient funds or user not found."

def handle_balance_inquiry(username):
    if username in user_balances:
        return True, f"Current balance: {user_balances[username]}"
    return False, "User not found."

def server():
    host = 'localhost'
    port = 5555
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        logging.info(f"Server listening on {host}:{port}")
        while True:
            conn, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, address))
            client_thread.start()

if __name__ == '__main__':
    server()
