import socket
import threading
import logging
from enconding import *
import base64


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
sharedKey = 'harkiratJASDEEPnavjeev'
user_credentials = {}
user_balances = {}

def authenticate_connection(conn):
    bankNonce = os.urandom(16)  

    atmNonce = conn.recv(4096)
    atmNonce = customDecrypt(base64.b64decode(atmNonce), sharedKey)

    returnMessage = bankNonce + b'||' + atmNonce
    returnMessage = customEncrypt(returnMessage, key=sharedKey)
    conn.sendall(base64.b64encode(returnMessage))


    recievedNonce = conn.recv(4096)
    recievedNonce = customDecrypt(base64.b64decode(recievedNonce), sharedKey)

    if recievedNonce == bankNonce:
        logging.info("Bank Has Authenticated Customer")

        masterKey1 = conn.recv(4096)
        masterKey1 = customDecrypt(base64.b64decode(masterKey1), sharedKey)
        logging.info(f"Master Key Recieved: {masterKey1}")
        # Derive encryption and MAC keys from the Master Secret
        encryption_key, mac_key = derive_keys(masterKey1)

        return encryption_key, mac_key  # Return derived keys for use in the session

    return False 

def handle_client(conn, address):
    logging.info(f"Connection from: {address}")
    if not authenticate_connection(conn):
        conn.close()
        logging.info(f"Failed to authenticate connection with {address}. Connection closed.")
        return
    
    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break  # Client has disconnected
            
            parts = data.split('||')
            if len(parts) < 2:
                logging.error("Invalid message format received.")
                conn.send(b"Invalid message format.")
                continue  # Continue listening for next command
            
            action = parts[0]
            username = parts[1]

            if action == "logout":
                logging.info(f"User {username} logged out.")
                break  
            
            if action == "register":
                password = parts[2]
                handle_registration(conn, username, password)
                user_balances[username] = 0
            elif action == "login":
                password = parts[2]
                handle_login(conn, username, password)
            elif action == "deposit":
                amount = float(parts[2])
                handle_deposit(conn, username, amount)
            elif action == "withdraw":
                amount = float(parts[2])
                handle_withdrawal(conn, username, amount)
            elif action == "balance":
                handle_balance_inquiry(conn, username)
            else:
                logging.warning(f"Unknown action received: {action}")
    except Exception as e:
        logging.error(f"Error handling client {address}: {e}")
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
