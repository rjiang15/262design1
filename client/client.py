#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Client for account and messaging functionalities (Phase 4.5).
This client uses Tkinter for the GUI.
It supports login, account creation, sending messages, reading messages,
listing accounts, and logging out.
It accepts command-line arguments for the server host and port.
"""

import argparse
import socket
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import threading

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Start the GUI client.")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host to connect to (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port to connect to (default: 54400)")
args = parser.parse_args()

SERVER_HOST = args.host
SERVER_PORT = args.port

def hash_password(password):
    """Return the SHA-256 hash of the given password as a hexadecimal string."""
    return hashlib.sha256(password.encode()).hexdigest()

def send_command(command):
    """
    Open a new socket connection to the server, send the command, and return the response.
    Each command is newline-terminated.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall((command + "\n").encode('utf-8'))
            # Use a larger buffer if necessary.
            data = s.recv(4096).decode('utf-8')
            return data.strip()
    except Exception as e:
        return f"ERROR: {e}"

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.session_username = None
        self.session_hash = None
        
        # Create a login frame.
        self.login_frame = tk.Frame(root)
        self.login_frame.pack(padx=10, pady=10)
        
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)
        
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)
        
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, pady=5)
        self.create_button = tk.Button(self.login_frame, text="Create Account", command=self.create_account)
        self.create_button.grid(row=2, column=1, pady=5)
        
        # Create the main frame for logged-in users (hidden initially).
        self.main_frame = tk.Frame(root)
        # Label to show the logged in username.
        self.logged_in_label = tk.Label(self.main_frame, text="Not logged in")
        self.logged_in_label.pack(pady=5)
        
        # Frame for sending messages.
        send_frame = tk.Frame(self.main_frame)
        send_frame.pack(pady=5)
        tk.Label(send_frame, text="Recipient:").grid(row=0, column=0)
        self.recipient_entry = tk.Entry(send_frame)
        self.recipient_entry.grid(row=0, column=1)
        tk.Label(send_frame, text="Message:").grid(row=1, column=0)
        self.message_entry = tk.Entry(send_frame, width=50)
        self.message_entry.grid(row=1, column=1)
        self.send_button = tk.Button(send_frame, text="Send Message", command=self.send_message)
        self.send_button.grid(row=2, column=0, columnspan=2, pady=5)
        
        # Frame for reading messages.
        read_frame = tk.Frame(self.main_frame)
        read_frame.pack(pady=5)
        tk.Label(read_frame, text="Number of messages to read:").grid(row=0, column=0)
        self.num_messages_entry = tk.Entry(read_frame, width=5)
        self.num_messages_entry.insert(0, "10")
        self.num_messages_entry.grid(row=0, column=1)
        self.read_button = tk.Button(read_frame, text="Read Messages", command=self.read_messages)
        self.read_button.grid(row=0, column=2, padx=5)
        
        # Scrolled text widget to display messages and responses.
        self.output_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=15)
        self.output_text.pack(pady=5)
        
        # Bottom frame for additional commands.
        bottom_frame = tk.Frame(self.main_frame)
        bottom_frame.pack(pady=5)
        self.list_button = tk.Button(bottom_frame, text="List Accounts", command=self.list_accounts)
        self.list_button.pack(side=tk.LEFT, padx=5)
        self.logout_button = tk.Button(bottom_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side=tk.LEFT, padx=5)
    
    def append_output(self, text):
        """Append text to the output text widget."""
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        hashed = hash_password(password)
        command = f"LOGIN {username} {hashed}"
        threading.Thread(target=self.run_command, args=(command, self.handle_login, username, hashed)).start()
    
    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        hashed = hash_password(password)
        command = f"CREATE {username} {hashed}"
        threading.Thread(target=self.run_command, args=(command, self.handle_create_account)).start()
    
    def logout(self):
        if self.session_username is None:
            return
        command = f"LOGOUT {self.session_username} {self.session_hash}"
        threading.Thread(target=self.run_command, args=(command, self.handle_logout)).start()
    
    def send_message(self):
        if self.session_username is None:
            messagebox.showerror("Error", "Not logged in")
            return
        recipient = self.recipient_entry.get().strip()
        message = self.message_entry.get().strip()
        if not recipient or not message:
            messagebox.showerror("Error", "Please enter recipient and message")
            return
        command = f"SEND {self.session_username} {self.session_hash} {recipient} {message}"
        threading.Thread(target=self.run_command, args=(command, self.handle_generic)).start()
    
    def read_messages(self):
        if self.session_username is None:
            messagebox.showerror("Error", "Not logged in")
            return
        num = self.num_messages_entry.get().strip()
        if not num.isdigit():
            messagebox.showerror("Error", "Enter a valid number")
            return
        command = f"READ {self.session_username} {self.session_hash} {num}"
        threading.Thread(target=self.run_command, args=(command, self.handle_generic)).start()
    
    def list_accounts(self):
        pattern = simpledialog.askstring("List Accounts", "Enter pattern (leave blank for all):", initialvalue="%")
        if pattern is None:
            return
        offset = simpledialog.askstring("List Accounts", "Enter offset (default 0):", initialvalue="0")
        if offset is None:
            offset = "0"
        limit = simpledialog.askstring("List Accounts", "Enter limit (default 10):", initialvalue="10")
        if limit is None:
            limit = "10"
        command = f"LIST {pattern} {offset} {limit}"
        threading.Thread(target=self.run_command, args=(command, self.handle_generic)).start()
    
    def run_command(self, command, callback, *args):
        """Run send_command in a separate thread and schedule the callback with the result."""
        response = send_command(command)
        self.root.after(0, callback, response, *args)
    
    def handle_login(self, response, username, hashed):
        if response.startswith("OK:"):
            self.session_username = username
            self.session_hash = hashed
            self.logged_in_label.config(text=f"Logged in as: {self.session_username}")
            self.login_frame.pack_forget()
            self.main_frame.pack(padx=10, pady=10)
        else:
            messagebox.showerror("Login Failed", response)
    
    def handle_create_account(self, response):
        if response.startswith("OK:"):
            messagebox.showinfo("Account Created", "Account successfully created. You can now log in.")
        else:
            messagebox.showerror("Error", response)
    
    def handle_logout(self, response):
        if response.startswith("OK:"):
            self.session_username = None
            self.session_hash = None
            self.main_frame.pack_forget()
            self.login_frame.pack(padx=10, pady=10)
            self.output_text.delete("1.0", tk.END)
            messagebox.showinfo("Logged Out", "You have been logged out.")
        else:
            messagebox.showerror("Error", response)
    
    def handle_generic(self, response):
        self.append_output(response)

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
