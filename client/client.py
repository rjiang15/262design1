#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Chat Client for conversation threads with live updates, new conversation,
and message deletion (Phase 4.5 and Extensions).
Uses Tkinter to provide a login screen, a conversation list, and a chat view
with a Treeview for selectable messages.
Accepts command-line arguments for server host and port.
"""

import argparse
import socket
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
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
        self.polling_job = None     # ID for the after() polling job

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

        # Left panel: Conversation list and account list options
        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)
        tk.Label(self.left_frame, text="Conversations").pack()
        self.convo_listbox = tk.Listbox(self.left_frame, width=30)
        self.convo_listbox.pack(fill=tk.Y, expand=True)
        self.convo_listbox.bind("<<ListboxSelect>>", self.on_convo_select)
        self.refresh_convo_button = tk.Button(self.left_frame, text="Refresh Conversations", command=self.refresh_conversations)
        self.refresh_convo_button.pack(pady=5)
        self.new_conv_button = tk.Button(self.left_frame, text="New Conversation", command=self.new_conversation)
        self.new_conv_button.pack(pady=5)

        # Right panel: Chat view using a Treeview for selectable messages
        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)
        tk.Label(self.right_frame, text="Chat").pack()
        self.chat_tree = ttk.Treeview(self.right_frame, columns=("ID", "From", "Message"), show="headings", selectmode="browse")
        self.chat_tree.heading("ID", text="ID")
        self.chat_tree.heading("From", text="From")
        self.chat_tree.heading("Message", text="Message")
        self.chat_tree.column("ID", width=50, anchor="center")
        self.chat_tree.column("From", width=100, anchor="center")
        self.chat_tree.column("Message", width=300)
        self.chat_tree.pack(fill=tk.BOTH, expand=True)
        tree_scroll = tk.Scrollbar(self.right_frame, orient="vertical", command=self.chat_tree.yview)
        self.chat_tree.configure(yscroll=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.delete_msg_button = tk.Button(self.right_frame, text="Delete Selected Message", command=self.delete_selected_message)
        self.delete_msg_button.pack(pady=5)
        
        # Message entry and send button for new messages
        bottom_frame = tk.Frame(self.right_frame)
        bottom_frame.pack(pady=5)
        self.message_entry = tk.Entry(bottom_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        self.send_chat_button = tk.Button(bottom_frame, text="Send", command=self.send_chat_message)
        self.send_chat_button.pack(side=tk.LEFT)

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
        self.cancel_polling()

    def refresh_conversations(self):
        if self.session_username is None:
            return
        command = f"LIST_CONVERSATIONS {self.session_username} {self.session_hash}"
        threading.Thread(target=self.run_command, args=(command, self.handle_list_conversations)).start()

    def new_conversation(self):
        # Use the LIST command to get all accounts.
        command = "LIST % 0 100"
        response = send_command(command)
        lines = response.splitlines()
        if len(lines) < 3:
            messagebox.showinfo("Info", "No users available")
            return
        # The first two lines are header info; the rest are usernames.
        users = lines[2:]
        if self.session_username in users:
            users.remove(self.session_username)
        if not users:
            messagebox.showinfo("Info", "No other users available.")
            return
        new_conv_win = tk.Toplevel(self.root)
        new_conv_win.title("New Conversation")
        tk.Label(new_conv_win, text="Select a user to start a conversation:").pack(pady=5)
        listbox = tk.Listbox(new_conv_win, width=30)
        listbox.pack(padx=10, pady=10)
        for user in users:
            listbox.insert(tk.END, user)
        def start_conv():
            if not listbox.curselection():
                messagebox.showerror("Error", "Please select a user")
                return
            index = listbox.curselection()[0]
            partner = listbox.get(index)
            self.current_convo = partner
            new_conv_win.destroy()
            self.load_conversation(partner)
            self.start_polling_conversation()
        start_button = tk.Button(new_conv_win, text="Start Conversation", command=start_conv)
        start_button.pack(pady=5)

    def on_convo_select(self, event):
        if not self.convo_listbox.curselection():
            return
        index = self.convo_listbox.curselection()[0]
        item = self.convo_listbox.get(index)
        try:
            partner = item.split(",")[0].split(":")[1].strip()
        except IndexError:
            return
        self.current_convo = partner
        self.load_conversation(partner)
        self.start_polling_conversation()

    def load_conversation(self, partner):
        if self.session_username is None:
            return
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

    def delete_selected_message(self):
        selected = self.chat_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a message to delete")
            return
        msg_id = self.chat_tree.item(selected[0])["values"][0]
        command = f"DELETE_MSG {self.session_username} {self.session_hash} {msg_id}"
        threading.Thread(target=self.run_command, args=(command, self.handle_delete_message)).start()

    def run_command(self, command, callback, *args):
        response = send_command(command)
        self.root.after(0, callback, response, *args)

    def handle_login(self, response, username, hashed):
        if response.startswith("OK:"):
            self.session_username = username
            self.session_hash = hashed
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
            self.chat_tree.delete(*self.chat_tree.get_children())
            self.convo_listbox.delete(0, tk.END)
            messagebox.showinfo("Logged Out", "You have been logged out.")
        else:
            messagebox.showerror("Error", response)

    def handle_list_conversations(self, response):
        self.convo_listbox.delete(0, tk.END)
        lines = response.splitlines()
        if lines:
            self.status_label.config(text=f"Logged in as: {self.session_username} ({lines[0]})")
            for line in lines[1:]:
                self.convo_listbox.insert(tk.END, line)

    def handle_load_conversation(self, response):
        self.chat_tree.delete(*self.chat_tree.get_children())
        lines = response.splitlines()
        for line in lines:
            try:
                parts = line.split(",")
                msg_id = parts[0].split(":")[1].strip()
                sender = parts[1].split(":")[1].strip()
                message = parts[2].split(":", 1)[1].strip()
                self.chat_tree.insert("", tk.END, values=(msg_id, sender, message))
            except Exception:
                self.chat_tree.insert("", tk.END, values=(line,))
        self.chat_tree.yview_moveto(1)

    def handle_send_chat(self, response):
        self.append_output(response)
        self.message_entry.delete(0, tk.END)
        if self.current_convo:
            self.load_conversation(self.current_convo)
            self.refresh_conversations()

    def handle_delete_message(self, response):
        self.append_output(response)
        if self.current_convo:
            self.load_conversation(self.current_convo)
            self.refresh_conversations()

    def handle_poll_response(self, response):
        if not response.startswith("OK: No new messages"):
            lines = response.splitlines()
            for line in lines:
                try:
                    parts = line.split(",")
                    msg_id = parts[0].split(":")[1].strip()
                    sender = parts[1].split(":")[1].strip()
                    message = parts[2].split(":", 1)[1].strip()
                    existing_ids = [self.chat_tree.item(item)["values"][0] for item in self.chat_tree.get_children()]
                    if msg_id not in existing_ids:
                        self.chat_tree.insert("", tk.END, values=(msg_id, sender, message))
                except Exception:
                    continue
            self.chat_tree.yview_moveto(1)
            self.refresh_conversations()

    def append_output(self, text):
        self.status_label.config(text=f"{self.session_username}: {text}")

    # --- Polling for live updates ---
    def start_polling_conversation(self):
        self.cancel_polling()
        self.poll_conversation()

    def poll_conversation(self):
        if self.session_username and self.current_convo:
            command = f"POLL_CONVO {self.session_username} {self.session_hash} {self.current_convo}"
            threading.Thread(target=self.run_command, args=(command, self.handle_poll_response)).start()
        self.polling_job = self.root.after(2000, self.poll_conversation)

    def cancel_polling(self):
        if self.polling_job:
            self.root.after_cancel(self.polling_job)
            self.polling_job = None

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
