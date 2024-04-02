import tkinter as tk
from tkinter import messagebox
import socket
import os
import base64
from enconding import *
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ClientApp:
    def __init__(self, master):
        self.sharedKey = bytearray(b'harkiratJASDEEPnavjeev')
        self.master = master
        self.bankSock = self.connect()
        self.master.title("Client Registration/Login")
        self.action_var = tk.StringVar(value="login")

        self.username_label = tk.Label(master, text="Username:")
        self.username_entry = tk.Entry(master)

        self.password_label = tk.Label(master, text="Password:")
        self.password_entry = tk.Entry(master, show="*")

        self.action_login = tk.Radiobutton(master, text="Login", variable=self.action_var, value="login")
        self.action_register = tk.Radiobutton(master, text="Register", variable=self.action_var, value="register")

        self.submit_button = tk.Button(master, text="Submit", command=self.submit_action)
        self.reset_button = tk.Button(master, text="Reset", command=self.reset_form)  # Reset button

        self.username_label.grid(row=0, column=0)
        self.username_entry.grid(row=0, column=1)
        self.password_label.grid(row=1, column=0)
        self.password_entry.grid(row=1, column=1)
        self.action_login.grid(row=2, column=0)
        self.action_register.grid(row=2, column=1)
        self.submit_button.grid(row=3, column=0)
        self.reset_button.grid(row=3, column=1) 

    def submit_action(self):
        action = self.action_var.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.communicate_with_server(action, username, password)

    def reset_form(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.submit_button['state'] = tk.NORMAL

    def clear_gui(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def on_login_success(self, username):
        self.logged_in_user = username
        self.clear_gui()
        self.show_transaction_ui()

    def show_transaction_ui(self):
        tk.Label(self.master, text=f"Logged in as {self.logged_in_user}").pack()

        self.action_var = tk.StringVar(value="deposit")  

        tk.Radiobutton(self.master, text="Deposit", variable=self.action_var, value="deposit").pack()
        tk.Radiobutton(self.master, text="Withdraw", variable=self.action_var, value="withdraw").pack()
        tk.Radiobutton(self.master, text="Balance Inquiry", variable=self.action_var, value="balance").pack()

        self.amount_entry = tk.Entry(self.master)
        self.amount_entry.pack()

        tk.Button(self.master, text="Submit", command=self.perform_transaction).pack()

    def perform_transaction(self):
        action = self.action_var.get()
        amount = self.amount_entry.get()
        self.communicate_with_server(action, self.logged_in_user, amount)
        self.amount_entry.delete(0, tk.END)

    def connect(self):
        try:
            bankSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bankSock.connect(('localhost', 5555))
            atmNonce = os.urandom(16)
            print("ATM Nonce:", atmNonce)  # Debugging message
            encryptedNonce = simpleEncrypt(atmNonce, self.sharedKey)
            bankSock.send(base64.b64encode(encryptedNonce))

            bankMessage = bankSock.recv(4096)
            bankMessage = base64.b64decode(bankMessage)
            bankMessage = simpleDecrypt(bankMessage, self.sharedKey)
            print("Decrypted Bank Message:", bankMessage)  # Debugging message
            bankNonce = bankMessage.split(b'||')[0]
            receivedNonce = bankMessage.split(b'||')[1]

            print("Received Bank Server Nonce:", bankNonce)  # Debugging message
            print("Received ATM Nonce from Bank:", receivedNonce)  # Debugging message
            if receivedNonce == atmNonce:
                logging.info("Customer Has Authenticated Bank")
                encryptedNonce = simpleEncrypt(bankNonce, key=self.sharedKey)
                bankSock.send(base64.b64encode(encryptedNonce))

                self.masterKey = createMasterKey()
                masterKey = simpleEncrypt(self.masterKey, key=self.sharedKey)
                bankSock.send(base64.b64encode(masterKey))
                logging.info(f"Shared Master Key to Bank: {self.masterKey}")

                # Derive encryption and MAC keys from the Master Secret
                self.encryption_key, self.mac_key = derive_keys(self.masterKey) # Returns two 16-byte keys
                print("Encryption Key:", self.encryption_key)  # Debugging message
                print("MAC Key:", self.mac_key)  # Debugging message

                # Store the mac_key as an attribute
                self.mac_key = self.mac_key
            else:
                print("Received Nonce did not match ATM Nonce. Authentication failed.")  # Debugging message
            return bankSock
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            return None





    def communicate_with_server(self, action, username, password_or_amount):
        if self.bankSock:
            try:
                # Prepare and send the encrypted message with MAC to the server
                message = f"{action}||{username}||{password_or_amount}"
                print("Sending message to server:", message)  # Debugging message
                mac = generate_mac(message.encode(), self.mac_key)
                encrypted_message = customEncrypt(message + '||' + base64.b64encode(mac).decode(), self.encryption_key)
                print("Encrypted message:", encrypted_message)  # Debugging message
                self.bankSock.sendall(encrypted_message)

                # Receive the encrypted response from the server
                encrypted_response = self.bankSock.recv(4096)
                print("Received encrypted response from server:", encrypted_response)  # Debugging message

                if encrypted_response:
                    decrypted_response = customDecrypt(encrypted_response, self.encryption_key)
                    print("Decrypted response:", decrypted_response)  # Debugging message
                    message_part, received_mac_encoded = decrypted_response.rsplit('||', 1)
                    received_mac = base64.b64decode(received_mac_encoded.encode())

                    # Verify the MAC
                    if verify_mac(message_part.encode(), self.mac_key, received_mac):
                        # If MAC is valid, show the message part in a messagebox
                        print("MAC verified")  # Debugging message

                        messagebox.showinfo("Response", message_part)
                        if action == "login" and "successful" in message_part:
                            self.on_login_success(username)
                    else:
                        # If MAC verification fails, show an error
                        messagebox.showerror("Error", "MAC verification failed.")
                else:
                    messagebox.showerror("Error", "No encrypted response received from the server.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Connection Error", "Not connected to the server.")




def main():
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
