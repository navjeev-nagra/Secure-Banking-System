import socket
import threading
import logging
from encryption import *
import base64
import binascii

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
sharedKey = bytearray(b'harkiratJASDEEPnavjeev')
user_credentials = {}
user_balances = {}

def authenticate_connection(conn):
    bankNonce = os.urandom(16)
    
    # Receive ATM nonce from the client
    atmNonce = conn.recv(4096)
    if not atmNonce:
        logging.error("Failed to receive ATM nonce from client.")
        return False
    
    # Add padding to the base64 encoded string before decoding
    atmNonce = atmNonce + b'=' * ((4 - len(atmNonce) % 4) % 4)

    try:
        # Decode the base64 encoded string
        atmNonce = base64.b64decode(atmNonce)
    except binascii.Error as e:
        logging.error(f"Error decoding base64: {e}")
        return False

    returnMessage = bankNonce + b'||' + atmNonce
    returnMessage = simpleEncrypt(returnMessage, key=sharedKey)
    conn.sendall(base64.b64encode(returnMessage))

    # Receive the decrypted nonce from the client
    receivedNonce = conn.recv(4096)
    if not receivedNonce:
        logging.error("Failed to receive decrypted nonce from client.")
        return False

    try:
        # Decrypt the received nonce
        receivedNonce = simpleDecrypt(base64.b64decode(receivedNonce), sharedKey)
    except Exception as e:
        logging.error(f"Error decrypting nonce: {e}")
        return False

    if receivedNonce == bankNonce:
        logging.info("Bank has authenticated the customer")

        # Receive and decrypt the master key from the client
        masterKey1 = conn.recv(4096)
        if not masterKey1:
            logging.error("Failed to receive master key from client.")
            return False

        try:
            masterKey1 = simpleDecrypt(base64.b64decode(masterKey1), sharedKey)
        except Exception as e:
            logging.error(f"Error decrypting master key: {e}")
            return False

        logging.info(f"Master Key Received: {masterKey1}")

        # Derive encryption and MAC keys from the Master Secret
        encryption_key, mac_key = derive_keys(masterKey1)

        return encryption_key, mac_key  # Return derived keys for use in the session

    return False


def handle_client(conn, address):
    logging.info(f"Connection from: {address}")

    # Authenticate the connection and obtain keys
    encryption_key, mac_key = authenticate_connection(conn)
    if not encryption_key or not mac_key:
        conn.close()
        logging.info(f"Failed to authenticate connection with {address}. Connection closed.")
        return
    
    try:
        while True:
            data = conn.recv(4096)
            print(data)
            if not data:
                break  # Client may have disconnected

            # Decrypt the data received from the client
            try:
                decrypted_data = customDecrypt(data, encryption_key)
            except Exception as decrypt_error:
                logging.error(f"Decryption error: {decrypt_error}")
                break  # Exit if decryption fails

            # Assuming the decrypted data format is "message||mac"
            # You might need to adjust based on how you format the encrypted message and MAC
            try:
                message, received_mac_encoded = decrypted_data.rsplit('||', 1)
                received_mac = base64.b64decode(received_mac_encoded)
            except ValueError:
                logging.error("Error splitting decrypted data into message and MAC")
                continue  # Skip to the next message if splitting fails

            # Verify the MAC
            if not verify_mac(message.encode(), mac_key, received_mac):
                logging.error("MAC verification failed.")
                continue  # Skip processing this message

            parts = message.split('||')
            if len(parts) < 2:
                logging.error("Invalid message format.")
                continue

            action, username = parts[0], parts[1]

            if action == "logout":
                logging.info(f"User {username} logged out.")
                break  
            
            if action == "register":
                password = parts[2]
                handle_registration(conn, username, password, encryption_key, mac_key)
                user_balances[username] = 0
            elif action == "login":
                password = parts[2]
                handle_login(conn, username, password, encryption_key, mac_key)
            elif action == "deposit":
                amount = float(parts[2])
                handle_deposit(conn, username, amount, encryption_key, mac_key)
            elif action == "withdraw":
                amount = float(parts[2])
                handle_withdrawal(conn, username, amount, encryption_key, mac_key)
            elif action == "balance":
                handle_balance_inquiry(conn, username, amount, encryption_key, mac_key)
            else:
                logging.warning(f"Unknown action received: {action}")
    except Exception as e:
        logging.error(f"Error handling client {address}: {e}")
    finally:
        conn.close()
        logging.info(f"Connection with {address} closed.")

def handle_registration(conn, username, password, encryption_key, mac_key):
    if username in user_credentials:
        message = "Username already exists."
        logging.warning(f"Registration attempt with existing username: {username}")
    else:
        user_credentials[username] = password
        message = "Registration successful."
        logging.info(f"New user registered: {username}")

    send_encrypted_message_with_mac(conn, message, encryption_key, mac_key)

def handle_login(conn, username, password, encryption_key, mac_key):
    if username in user_credentials and user_credentials[username] == password:
        message = "Login successful."
        logging.info(f"User logged in: {username}")
    else:
        message = "Login failed."
        logging.warning(f"Failed login attempt for username: {username}")

    send_encrypted_message_with_mac(conn, message, encryption_key, mac_key)



def handle_deposit(conn, username, amount, encryption_key, mac_key):
    if username in user_balances:
        user_balances[username] += amount
        message = "Deposit successful."
        logging.info(f"{username} deposited ${amount}")
    else:
        conn.send(b"Deposit failed.")
        logging.warning(f"Failed deposit attempt for username: {username}")

    send_encrypted_message_with_mac(conn, message, encryption_key, mac_key)



def handle_withdrawal(conn, username, amount, encryption_key, mac_key):
    if username in user_balances and user_balances[username] >= amount:
        user_balances[username] -= amount
        message = "Withdrawal successful."
        logging.info(f"{username} withdrew ${amount}")
    else:
        conn.send(b"Withdrawal failed.")
        logging.warning(f"Failed withdrawal attempt for username: {username}")

    send_encrypted_message_with_mac(conn, message, encryption_key, mac_key)


def handle_balance_inquiry(conn, username, amount, encryption_key, mac_key):
    if username in user_balances:
        message = f"Current balance: ${user_balances[username]}"
        logging.info(f"Current balance for {username}: ${user_balances[username]}")
    else:
        conn.send(b"Balance inquiry failed.")
        logging.warning(f"Failed balance inquiry attempt for username: {username}")

    send_encrypted_message_with_mac(conn, message, encryption_key, mac_key)



def send_encrypted_message_with_mac(conn, message, encryption_key, mac_key):
    # Append the MAC to the message before encryption
    mac = generate_mac(message.encode(), mac_key)
    combined_message = message + '||' + base64.b64encode(mac).decode()
    encrypted_message = customEncrypt(combined_message, encryption_key)

    # Send the encrypted message
    conn.sendall(encrypted_message)


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
