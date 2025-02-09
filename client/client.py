#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Client for chat with conversation threads (Phase 4.5 and Extensions).
Uses Tkinter to provide a login screen, a conversation list, and a chat view.
Accepts command-line arguments for server host and port.
"""

import argparse
import socket
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import threading

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Start the GUI chat client.")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host to connect to (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port to connect to (default: 54400)")
args = parser.parse_args()
SERVER_HOST = args.host
SERVER_PORT = args.port

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_command(command):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall((command + "\n").encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            return data.strip()
    except Exception as e:
        return f"ERROR: {e}"

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.session_username = None
        self.session_hash = None
        self.current_convo = None  # Currently selected conversation partner

        # --- Login Frame ---
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

        # --- Main Frame (post-login) ---
        self.main_frame = tk.Frame(root)
        self.status_label = tk.Label(self.main_frame, text="Not logged in")
        self.status_label.pack(pady=5)

        # Left panel: Conversation list
        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)
        tk.Label(self.left_frame, text="Conversations").pack()
        self.convo_listbox = tk.Listbox(self.left_frame, width=30)
        self.convo_listbox.pack(fill=tk.Y, expand=True)
        self.convo_listbox.bind("<<ListboxSelect>>", self.on_convo_select)
        self.refresh_convo_button = tk.Button(self.left_frame, text="Refresh Conversations", command=self.refresh_conversations)
        self.refresh_convo_button.pack(pady=5)

        # Right panel: Chat view
        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)
        tk.Label(self.right_frame, text="Chat").pack()
        self.chat_display = scrolledtext.ScrolledText(self.right_frame, wrap=tk.WORD, width=60, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        self.message_entry = tk.Entry(self.right_frame, width=50)
        self.message_entry.pack(pady=5, side=tk.LEFT, padx=5)
        self.send_chat_button = tk.Button(self.right_frame, text="Send", command=self.send_chat_message)
        self.send_chat_button.pack(pady=5, side=tk.LEFT)

        # Logout button
        self.logout_button = tk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.pack(pady=5)

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

    def refresh_conversations(self):
        if self.session_username is None:
            return
        # Use the new command: LIST_CONVERSATIONS
        command = f"LIST_CONVERSATIONS {self.session_username} {self.session_hash}"
        threading.Thread(target=self.run_command, args=(command, self.handle_list_conversations)).start()

    def on_convo_select(self, event):
        if not self.convo_listbox.curselection():
            return
        index = self.convo_listbox.curselection()[0]
        item = self.convo_listbox.get(index)
        # Expect item format: "Partner: bob, Unread: 2, Last: ..."
        try:
            partner = item.split(",")[0].split(":")[1].strip()
        except IndexError:
            return
        self.current_convo = partner
        self.load_conversation(partner)

    def load_conversation(self, partner):
        if self.session_username is None:
            return
        # Use the new command: READ_CONVO
        command = f"READ_CONVO {self.session_username} {self.session_hash} {partner} 50"
        threading.Thread(target=self.run_command, args=(command, self.handle_load_conversation)).start()

    def send_chat_message(self):
        if self.session_username is None or not self.current_convo:
            messagebox.showerror("Error", "No conversation selected")
            return
        msg = self.message_entry.get().strip()
        if not msg:
            messagebox.showerror("Error", "Enter a message to send")
            return
        command = f"SEND {self.session_username} {self.session_hash} {self.current_convo} {msg}"
        threading.Thread(target=self.run_command, args=(command, self.handle_send_chat)).start()

    def run_command(self, command, callback, *args):
        response = send_command(command)
        self.root.after(0, callback, response, *args)

    def handle_login(self, response, username, hashed):
        if response.startswith("OK:"):
            self.session_username = username
            self.session_hash = hashed
            # Update status label with unread count from login response.
            # (Assuming login response ends with ", unread messages: X")
            self.status_label.config(text=f"Logged in as: {self.session_username} ({response.split(',')[-1].strip()})")
            self.login_frame.pack_forget()
            self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.refresh_conversations()
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
            self.chat_display.delete("1.0", tk.END)
            self.convo_listbox.delete(0, tk.END)
            messagebox.showinfo("Logged Out", "You have been logged out.")
        else:
            messagebox.showerror("Error", response)

    def handle_list_conversations(self, response):
        self.convo_listbox.delete(0, tk.END)
        lines = response.splitlines()
        # First line contains the total unread count.
        if lines:
            self.status_label.config(text=f"Logged in as: {self.session_username} ({lines[0]})")
            for line in lines[1:]:
                self.convo_listbox.insert(tk.END, line)

    def handle_load_conversation(self, response):
        self.chat_display.delete("1.0", tk.END)
        self.chat_display.insert(tk.END, response + "\n")

    def handle_send_chat(self, response):
        self.append_output(response)
        self.message_entry.delete(0, tk.END)
        if self.current_convo:
            self.load_conversation(self.current_convo)
            self.refresh_conversations()

    def append_output(self, text):
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
