#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Chat Client for conversation threads with live updates, new conversation,
and dynamic unread counters. Uses Tkinter to provide a separate login screen and a chat view.
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
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port (default: 54400)")
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
        self.current_convo = None  # currently selected conversation partner
        self.polling_job = None     # for live updates
        # When loading unread messages via prompt, suppress live polling.
        self.suppress_polling = False

        # --- Login Frame (visible initially) ---
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

        # --- Main Frame (hidden until login) ---
        self.main_frame = tk.Frame(root)
        self.status_label = tk.Label(self.main_frame, text="Not logged in")
        self.status_label.pack(pady=5)

        # Left panel: Conversation list.
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

        # Right panel: Chat view.
        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)
        tk.Label(self.right_frame, text="Chat").pack()
        tk.Label(self.right_frame, text="(Double-click a message to view full text)", fg="gray", font=("Helvetica", 9)).pack(pady=(0,5))
        self.chat_tree = ttk.Treeview(self.right_frame, columns=("ID", "From", "Message"), show="headings", selectmode="extended")
        self.chat_tree.heading("ID", text="ID")
        self.chat_tree.heading("From", text="From")
        self.chat_tree.heading("Message", text="Message")
        self.chat_tree.column("ID", width=50, anchor="center", stretch=False)
        self.chat_tree.column("From", width=100, anchor="center", stretch=False)
        self.chat_tree.column("Message", width=600, anchor="w", stretch=True)
        self.chat_tree.pack(fill=tk.BOTH, expand=True)
        tree_scroll = tk.Scrollbar(self.right_frame, orient="vertical", command=self.chat_tree.yview)
        self.chat_tree.configure(yscroll=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.delete_msg_button = tk.Button(self.right_frame, text="Delete Selected Message(s)", command=self.delete_selected_message)
        self.delete_msg_button.pack(pady=5)
        self.chat_tree.bind("<Double-1>", self.show_full_message)
        
        # "View More" button.
        self.view_more_button = tk.Button(self.right_frame, text="View More", command=self.view_more_messages)
        self.view_more_button.pack(pady=5)

        # Bottom frame: Message entry and send button.
        bottom_frame = tk.Frame(self.right_frame)
        bottom_frame.pack(pady=5)
        self.msg_count_label = tk.Label(bottom_frame, text="0/256", fg="white", bg="black")
        self.msg_count_label.pack(side=tk.LEFT, padx=(0,5))
        self.message_entry = tk.Entry(bottom_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        self.message_entry.bind("<KeyRelease>", self.update_msg_count)
        self.send_chat_button = tk.Button(bottom_frame, text="Send", command=self.send_chat_message)
        self.send_chat_button.pack(side=tk.LEFT)

        # Logout and Delete Account buttons.
        self.logout_button = tk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.pack(pady=5)
        self.delete_account_button = tk.Button(self.main_frame, text="Delete Account", command=self.delete_account)
        self.delete_account_button.pack(pady=5)

    def update_msg_count(self, event):
        text = self.message_entry.get()
        length = len(text)
        self.msg_count_label.config(text=f"{length}/256", fg="red" if length > 256 else "white")

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
        self.suppress_polling = False

    def delete_account(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete your account? This action cannot be undone."):
            command = f"DELETE {self.session_username} {self.session_hash}"
            threading.Thread(target=self.run_command, args=(command, self.handle_delete_account)).start()

    def handle_delete_account(self, response):
        if response.startswith("OK:"):
            messagebox.showinfo("Account Deleted", "Your account has been deleted.")
            self.session_username = None
            self.session_hash = None
            self.main_frame.pack_forget()
            self.login_frame.pack(padx=10, pady=10)
            self.chat_tree.delete(*self.chat_tree.get_children())
            self.convo_listbox.delete(0, tk.END)
        else:
            messagebox.showerror("Error", response)

    def refresh_conversations(self):
        if self.session_username is None:
            return
        command = f"LIST_CONVERSATIONS {self.session_username} {self.session_hash}"
        threading.Thread(target=self.run_command, args=(command, self.handle_list_conversations)).start()

    def new_conversation(self):
        command = "LIST % 0 100"
        response = send_command(command)
        lines = response.splitlines()
        if len(lines) < 3:
            messagebox.showinfo("Info", "No users available")
            return
        users = lines[2:]
        if self.session_username in users:
            users.remove(self.session_username)
        if not users:
            messagebox.showinfo("Info", "No other users available.")
            return
        new_conv_win = tk.Toplevel(self.root)
        new_conv_win.title("New Conversation")
        tk.Label(new_conv_win, text="Search for a user:").pack(pady=5)
        search_var = tk.StringVar()
        search_entry = tk.Entry(new_conv_win, textvariable=search_var)
        search_entry.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(new_conv_win, text="Select a user to start a conversation:").pack(pady=5)
        listbox_frame = tk.Frame(new_conv_win)
        listbox_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical")
        listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set, width=30)
        scrollbar.config(command=listbox.yview)
        scrollbar.pack(side="right", fill="y")
        listbox.pack(side="left", fill="both", expand=True)
        full_user_list = users[:]  # copy full list
        for user in full_user_list:
            listbox.insert(tk.END, user)
        def update_list(*args):
            search_text = search_var.get().lower()
            listbox.delete(0, tk.END)
            for user in full_user_list:
                if search_text in user.lower():
                    listbox.insert(tk.END, user)
        search_var.trace("w", update_list)
        def start_conv():
            if not listbox.curselection():
                messagebox.showerror("Error", "Please select a user")
                return
            index = listbox.curselection()[0]
            partner = listbox.get(index)
            self.current_convo = partner
            new_conv_win.destroy()
            # For a new conversation, load full history.
            self.load_full_conversation(partner, 50)
            self.suppress_polling = False
            self.start_polling_conversation()
        start_button = tk.Button(new_conv_win, text="Start Conversation", command=start_conv)
        start_button.pack(pady=5)

    def on_convo_select(self, event):
        if not self.convo_listbox.curselection():
            return
        index = self.convo_listbox.curselection()[0]
        selected_text = self.convo_listbox.get(index)
        # Expected format: "Partner: bob, Unread: 5, Last: bob: Hi!"
        try:
            parts = selected_text.split(",")
            partner = parts[0].split(":")[1].strip()
            unread_str = parts[1].split(":")[1].strip()
            unread = int(unread_str)
        except Exception:
            partner = selected_text
            unread = 0
        self.current_convo = partner
        if unread > 0:
            # When there are unread messages, prompt the user.
            self.suppress_polling = True
            self.prompt_for_unread_messages(partner, unread)
        else:
            self.load_full_conversation(partner, 50)
            self.suppress_polling = False
            self.start_polling_conversation()

    def prompt_for_unread_messages(self, partner, unread):
        num = tk.simpledialog.askinteger("Unread Messages",
                                         f"This conversation with {partner} has {unread} unread messages.\n"
                                         "How many would you like to view?",
                                         parent=self.root,
                                         minvalue=1,
                                         maxvalue=unread)
        if num is None:
            return
        self.load_unread_messages(partner, num)
        # Immediately refresh conversations so that unread counters update.
        self.refresh_conversations()
        self.suppress_polling = True

    def load_unread_messages(self, partner, n):
        if self.session_username is None:
            return
        command = f"READ_CONVO {self.session_username} {self.session_hash} {partner} {n}"
        threading.Thread(target=self.run_command, args=(command, self.handle_append_new_messages)).start()

    def load_full_conversation(self, partner, n):
        if self.session_username is None:
            return
        command = f"READ_FULL_CONVO {self.session_username} {self.session_hash} {partner} {n}"
        self.chat_tree.delete(*self.chat_tree.get_children())
        threading.Thread(target=self.run_command, args=(command, self.handle_load_conversation)).start()

    def handle_append_new_messages(self, response, *args):
        new_messages = []
        lines = response.splitlines()
        for line in lines:
            try:
                parts = line.split("|||")
                if len(parts) >= 3:
                    msg_id = parts[0].strip()
                    sender = parts[1].strip()
                    message = parts[2].strip()
                    new_messages.append((msg_id, sender, message))
                else:
                    new_messages.append((line,))
            except Exception:
                new_messages.append((line,))
        existing_ids = {self.chat_tree.item(item)["values"][0] for item in self.chat_tree.get_children()}
        for msg in new_messages:
            if msg[0] not in existing_ids:
                self.chat_tree.insert("", tk.END, values=msg)
        self.chat_tree.yview_moveto(1)

    def handle_load_conversation(self, response, *args):
        # Clear and reload full conversation.
        new_messages = []
        lines = response.splitlines()
        for line in lines:
            try:
                parts = line.split("|||")
                if len(parts) >= 3:
                    msg_id = parts[0].strip()
                    sender = parts[1].strip()
                    message = parts[2].strip()
                    new_messages.append((msg_id, sender, message))
                else:
                    new_messages.append((line,))
            except Exception:
                new_messages.append((line,))
        self.chat_tree.delete(*self.chat_tree.get_children())
        for msg in new_messages:
            self.chat_tree.insert("", tk.END, values=msg)
        self.chat_tree.yview_moveto(1)

    def view_more_messages(self):
        response = send_command(f"LIST_CONVERSATIONS {self.session_username} {self.session_hash}")
        lines = response.splitlines()
        unread = 0
        for line in lines[1:]:
            if f"Partner: {self.current_convo}" in line:
                try:
                    unread = int(line.split("Unread:")[1].split(",")[0].strip())
                except Exception:
                    unread = 0
                break
        if unread > 0:
            self.prompt_for_unread_messages(self.current_convo, unread)
        else:
            self.load_full_conversation(self.current_convo, 50)
            self.suppress_polling = False
            self.start_polling_conversation()

    def load_conversation(self, partner):
        self.load_full_conversation(partner, 50)
        self.suppress_polling = False
        self.start_polling_conversation()

    def send_chat_message(self):
        if self.session_username is None or not self.current_convo:
            messagebox.showerror("Error", "No conversation selected")
            return
        msg = self.message_entry.get().strip()
        if not msg:
            messagebox.showerror("Error", "Enter a message to send")
            return
        if len(msg) > 256:
            messagebox.showerror("Error", "Message too long. Maximum allowed is 256 characters.")
            return
        command = f"SEND {self.session_username} {self.session_hash} {self.current_convo} {msg}"
        threading.Thread(target=self.run_command, args=(command, self.handle_send_chat)).start()

    def delete_selected_message(self):
        selected = self.chat_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select one or more messages to delete")
            return
        msg_ids = []
        for item in selected:
            msg_id = self.chat_tree.item(item)["values"][0]
            msg_ids.append(str(msg_id))
        ids_str = ",".join(msg_ids)
        command = f"DELETE_MSG {self.session_username} {self.session_hash} {ids_str}"
        threading.Thread(target=self.run_command, args=(command, self.handle_delete_message)).start()

    def run_command(self, command, callback, *args):
        response = send_command(command)
        self.root.after(0, callback, response, *args)

    def handle_login(self, response, username, hashed):
        if response.startswith("OK:"):
            self.session_username = username
            self.session_hash = hashed
            # Update header with the unread count (from the first line of LIST_CONVERSATIONS).
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
            # Update header with current unread total.
            self.status_label.config(text=f"Logged in as: {self.session_username} ({lines[0]})")
            for line in lines[1:]:
                self.convo_listbox.insert(tk.END, line)

    def handle_send_chat(self, response):
        self.append_output(response)
        self.message_entry.delete(0, tk.END)
        self.update_msg_count(None)
        if self.current_convo:
            self.load_full_conversation(self.current_convo, 50)
            self.suppress_polling = False
            self.refresh_conversations()
            self.start_polling_conversation()

    def handle_delete_message(self, response):
        self.append_output(response)
        if self.current_convo:
            self.load_full_conversation(self.current_convo, 50)
            self.refresh_conversations()

    def handle_poll_response(self, response):
        if self.suppress_polling:
            return
        if not response.startswith("OK: No new messages"):
            lines = response.splitlines()
            for line in lines:
                try:
                    parts = line.split("|||")
                    if len(parts) >= 3:
                        msg_id = parts[0].strip()
                        sender = parts[1].strip()
                        message = parts[2].strip()
                        existing_ids = {self.chat_tree.item(item)["values"][0] for item in self.chat_tree.get_children()}
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
        if not self.suppress_polling:
            self.cancel_polling()
            self.poll_conversation()

    def poll_conversation(self):
        if self.session_username and self.current_convo and not self.suppress_polling:
            command = f"POLL_CONVO {self.session_username} {self.session_hash} {self.current_convo}"
            threading.Thread(target=self.run_command, args=(command, self.handle_poll_response)).start()
        self.polling_job = self.root.after(2000, self.poll_conversation)

    def cancel_polling(self):
        if self.polling_job:
            self.root.after_cancel(self.polling_job)
            self.polling_job = None

    def show_full_message(self, event):
        selected = self.chat_tree.selection()
        if not selected:
            return
        item = self.chat_tree.item(selected[0])
        values = item["values"]
        if not values or len(values) < 3:
            return
        full_message = values[2]
        popup = tk.Toplevel(self.root)
        popup.title("Full Message")
        text_widget = tk.Text(popup, wrap="word", width=80, height=10)
        text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, full_message)
        text_widget.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
