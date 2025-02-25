#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Chat Client for conversation threads with live updates, new conversation,
and dynamic unread counters. Now uses gRPC calls to replicate exactly
the logic from your custom protocol client.py.
"""

import argparse
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import threading
import re
import grpc

from google.protobuf.empty_pb2 import Empty
import chat_pb2
import chat_pb2_grpc


# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Start the gRPC chat client.")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=50051, help="Server port (default: 50051)")
args = parser.parse_args()
SERVER_ADDRESS = f"{args.host}:{args.port}"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Create a global channel + stub
channel = grpc.insecure_channel(SERVER_ADDRESS)
stub = chat_pb2_grpc.ChatServiceStub(channel)


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("gRPC Chat Client")
        self.session_username = None
        self.session_hash = None
        self.current_convo = None
        self.polling_job = None
        self.suppress_polling = False

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

        # --- Main Frame ---
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
        self.new_conv_button = tk.Button(self.left_frame, text="New Conversation", command=self.new_conversation)
        self.new_conv_button.pack(pady=5)

        # Right panel: Chat view
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

        # "View More" button
        self.view_more_button = tk.Button(self.right_frame, text="View More", command=self.view_more_messages)
        self.view_more_button.pack(pady=5)

        # Bottom frame: message entry + send
        bottom_frame = tk.Frame(self.right_frame)
        bottom_frame.pack(pady=5)
        self.msg_count_label = tk.Label(bottom_frame, text="0/256", fg="white", bg="black")
        self.msg_count_label.pack(side=tk.LEFT, padx=(0,5))
        self.message_entry = tk.Entry(bottom_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        self.message_entry.bind("<KeyRelease>", self.update_msg_count)
        self.send_chat_button = tk.Button(bottom_frame, text="Send", command=self.send_chat_message)
        self.send_chat_button.pack(side=tk.LEFT)

        # Logout + Delete Account buttons
        self.logout_button = tk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.pack(pady=5)
        self.delete_account_button = tk.Button(self.main_frame, text="Delete Account", command=self.delete_account)
        self.delete_account_button.pack(pady=5)

    # ---------------------------
    #  UI helpers
    # ---------------------------
    def update_msg_count(self, event):
        text = self.message_entry.get()
        length = len(text)
        self.msg_count_label.config(text=f"{length}/256", fg="red" if length > 256 else "white")

    def append_output(self, text):
        """Helper to show status messages at the top label."""
        self.status_label.config(text=f"{self.session_username}: {text}")

    # ---------------------------
    #  Auth / Accounts
    # ---------------------------
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        hashed = hash_password(password)
        req = chat_pb2.AccountRequest(username=username, hashed_password=hashed)
        threading.Thread(target=self._login_thread, args=(req, username, hashed)).start()

    def _login_thread(self, req, username, hashed):
        response = stub.Login(req)
        self.root.after(0, self.handle_login, response, username, hashed)

    def handle_login(self, response, username, hashed):
        if response.status.startswith("OK"):
            self.session_username = username
            self.session_hash = hashed
            self.status_label.config(text=f"Logged in as: {username} ({response.message})")
            self.login_frame.pack_forget()
            self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.refresh_conversations()
        else:
            messagebox.showerror("Login Failed", response.message)

    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        hashed = hash_password(password)
        req = chat_pb2.AccountRequest(username=username, hashed_password=hashed)
        threading.Thread(target=self._create_account_thread, args=(req,)).start()

    def _create_account_thread(self, req):
        response = stub.CreateAccount(req)
        self.root.after(0, self.handle_create_account, response)

    def handle_create_account(self, response):
        if response.status.startswith("OK"):
            messagebox.showinfo("Account Created", "Account successfully created. You can now log in.")
        else:
            messagebox.showerror("Error", response.message)

    def logout(self):
        if not self.session_username:
            return
        req = chat_pb2.AccountRequest(username=self.session_username, hashed_password=self.session_hash)
        threading.Thread(target=self._logout_thread, args=(req,)).start()

        self.cancel_polling()
        self.suppress_polling = False

    def _logout_thread(self, req):
        response = stub.Logout(req)
        self.root.after(0, self.handle_logout, response)

    def handle_logout(self, response):
        if response.status.startswith("OK"):
            self.session_username = None
            self.session_hash = None
            self.main_frame.pack_forget()
            self.login_frame.pack(padx=10, pady=10)
            self.chat_tree.delete(*self.chat_tree.get_children())
            self.convo_listbox.delete(0, tk.END)
            messagebox.showinfo("Logged Out", "You have been logged out.")
        else:
            messagebox.showerror("Error", response.message)

    def delete_account(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete your account? This action cannot be undone."):
            req = chat_pb2.AccountRequest(username=self.session_username, hashed_password=self.session_hash)
            threading.Thread(target=self._delete_account_thread, args=(req,)).start()

    def _delete_account_thread(self, req):
        response = stub.DeleteAccount(req)
        self.root.after(0, self.handle_delete_account, response)

    def handle_delete_account(self, response):
        if response.status.startswith("OK"):
            messagebox.showinfo("Account Deleted", "Your account has been deleted.")
            self.session_username = None
            self.session_hash = None
            self.main_frame.pack_forget()
            self.login_frame.pack(padx=10, pady=10)
            self.chat_tree.delete(*self.chat_tree.get_children())
            self.convo_listbox.delete(0, tk.END)
        else:
            messagebox.showerror("Error", response.message)

    # ---------------------------
    #  LIST / new conversation
    # ---------------------------
    def refresh_conversations(self):
        if not self.session_username:
            return
        req = chat_pb2.ListConversationsRequest(
            username=self.session_username,
            hashed_password=self.session_hash
        )
        threading.Thread(target=self._list_conversations_thread, args=(req,)).start()

    def _list_conversations_thread(self, req):
        resp = stub.ListConversations(req)
        self.root.after(0, self.handle_list_conversations, resp)

    def handle_list_conversations(self, response):
        self.convo_listbox.delete(0, tk.END)
        header = f"Total unread: {response.total_unread}"
        self.status_label.config(text=f"Logged in as: {self.session_username} ({header})")
        for conv in response.conversations:
            line = f"Partner: {conv.partner}, Unread: {conv.unread}, Last: {conv.last_message}"
            self.convo_listbox.insert(tk.END, line)

    def new_conversation(self):
        # This replicates your logic of calling "LIST % 0 100"
        req = chat_pb2.ListRequest(pattern="%", offset=0, limit=100)
        response = stub.List(req)
        # response has "accounts" repeated field
        # first check if response.status == "OK" ...
        if response.status.startswith("ERROR"):
            messagebox.showerror("Error", response.message)
            return
        if len(response.accounts) < 1:
            messagebox.showinfo("Info", "No users available")
            return
        # remove self if present
        users = list(response.accounts)
        if self.session_username in users:
            users.remove(self.session_username)
        if not users:
            messagebox.showinfo("Info", "No other users available.")
            return

        # Show the new conversation dialog
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
        scrollbar.pack(side="right", fill=tk.Y)
        listbox.pack(side="left", fill="both", expand=True)

        full_user_list = users[:]
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
            self.load_full_conversation(partner, 50)
            self.suppress_polling = False
            self.start_polling_conversation()

        tk.Button(new_conv_win, text="Start Conversation", command=start_conv).pack(pady=5)

    # ---------------------------
    #  Conversation selection
    # ---------------------------
    def on_convo_select(self, event):
        if not self.convo_listbox.curselection():
            return
        index = self.convo_listbox.curselection()[0]
        selected_text = self.convo_listbox.get(index)
        # try to parse "Partner: X, Unread: Y, Last: ..."
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
            self.suppress_polling = True
            self.prompt_for_unread_messages(partner, unread)
        else:
            self.load_full_conversation(partner, 50)
            self.suppress_polling = False
            self.start_polling_conversation()

    # Replicates "how many unread messages to load"
    def prompt_for_unread_messages(self, partner, unread):
        num = simpledialog.askinteger(
            "Unread Messages",
            f"This conversation with {partner} has {unread} unread messages.\nHow many would you like to view?",
            parent=self.root,
            minvalue=1,
            maxvalue=unread
        )
        if num is None:
            return
        self.load_unread_messages(partner, num)
        self.refresh_conversations()
        self.suppress_polling = True

    def load_unread_messages(self, partner, n):
        # This replicates "READ_CONVO username hash partner n"
        req = chat_pb2.ReadConvoRequest(
            username=self.session_username,
            hashed_password=self.session_hash,
            other_user=partner,
            n=n
        )
        threading.Thread(target=self._load_unread_thread, args=(req,)).start()

    def _load_unread_thread(self, req):
        resp = stub.ReadConvo(req)
        self.root.after(0, self.handle_append_new_messages, resp)

    def handle_append_new_messages(self, response):
        if response.status.startswith("ERROR"):
            # If it's the "allowed maximum value is X" case, replicate your existing logic
            if "The allowed maximum value is" in response.message:
                messagebox.showerror("Error", response.message)
                m = re.search(r"The allowed maximum value is (\d+)", response.message)
                if m:
                    allowed = int(m.group(1))
                    self.prompt_for_unread_messages(self.current_convo, allowed)
            else:
                messagebox.showerror("Error", response.message)
            return

        # otherwise, append messages
        for msg in response.messages:
            existing_ids = {
                self.chat_tree.item(item)["values"][0]
                for item in self.chat_tree.get_children()
            }
            if msg.id not in existing_ids:
                self.chat_tree.insert("", tk.END, values=(msg.id, msg.sender, msg.content))
        self.chat_tree.yview_moveto(1)
        self.refresh_conversations()

    # ---------------------------
    #  READ_FULL_CONVO
    # ---------------------------
    def load_full_conversation(self, partner, n):
        self.chat_tree.delete(*self.chat_tree.get_children())
        req = chat_pb2.ReadConvoRequest(
            username=self.session_username,
            hashed_password=self.session_hash,
            other_user=partner,
            n=n
        )
        # We specifically call ReadFullConvo
        threading.Thread(target=self._load_full_convo_thread, args=(req,)).start()

    def _load_full_convo_thread(self, req):
        resp = stub.ReadFullConvo(req)
        self.root.after(0, self.handle_load_conversation, resp)

    def handle_load_conversation(self, response):
        if response.status.startswith("ERROR"):
            messagebox.showerror("Error", response.message)
            return
        self.chat_tree.delete(*self.chat_tree.get_children())
        for msg in response.messages:
            self.chat_tree.insert("", tk.END, values=(msg.id, msg.sender, msg.content))
        self.chat_tree.yview_moveto(1)

    # ---------------------------
    #  "View More" logic
    # ---------------------------
    def view_more_messages(self):
        # This replicates the logic where we check how many unread in this conversation
        req = chat_pb2.ListConversationsRequest(
            username=self.session_username,
            hashed_password=self.session_hash
        )
        resp = stub.ListConversations(req)
        unread = 0
        for conv in resp.conversations:
            if conv.partner == self.current_convo:
                unread = conv.unread
                break
        if unread > 0:
            self.prompt_for_unread_messages(self.current_convo, unread)
        else:
            self.load_full_conversation(self.current_convo, 50)
            self.suppress_polling = False
            self.start_polling_conversation()

    # ---------------------------
    #  SEND
    # ---------------------------
    def send_chat_message(self):
        if not self.session_username or not self.current_convo:
            messagebox.showerror("Error", "No conversation selected")
            return
        msg = self.message_entry.get().strip()
        if not msg:
            messagebox.showerror("Error", "Enter a message to send")
            return
        if len(msg) > 256:
            messagebox.showerror("Error", "Message too long. Maximum allowed is 256 characters.")
            return
        req = chat_pb2.SendMessageRequest(
            sender=self.session_username,
            hashed_password=self.session_hash,
            recipient=self.current_convo,
            message=msg
        )
        threading.Thread(target=self._send_chat_thread, args=(req,)).start()

    def _send_chat_thread(self, req):
        response = stub.SendMessage(req)
        self.root.after(0, self.handle_send_chat, response)

    def handle_send_chat(self, response):
        self.append_output(response.message)
        if response.status.startswith("OK"):
            self.message_entry.delete(0, tk.END)
            self.update_msg_count(None)
            self.load_full_conversation(self.current_convo, 50)
            self.suppress_polling = False
            self.refresh_conversations()
            self.start_polling_conversation()
        else:
            messagebox.showerror("Error", response.message)

    # ---------------------------
    #  DELETE_MSG
    # ---------------------------
    def delete_selected_message(self):
        selected = self.chat_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select one or more messages to delete")
            return
        msg_ids = [str(self.chat_tree.item(item)["values"][0]) for item in selected]
        ids_str = ",".join(msg_ids)
        req = chat_pb2.DeleteMessageRequest(
            username=self.session_username,
            hashed_password=self.session_hash,
            message_ids=ids_str
        )
        threading.Thread(target=self._delete_message_thread, args=(req,)).start()

    def _delete_message_thread(self, req):
        response = stub.DeleteMessage(req)
        self.root.after(0, self.handle_delete_message, response)

    def handle_delete_message(self, response):
        self.append_output(response.message)
        if response.status.startswith("OK"):
            self.load_full_conversation(self.current_convo, 50)
            self.refresh_conversations()
        else:
            messagebox.showerror("Error", response.message)

    # ---------------------------
    #  Polling (POLL_CONVO)
    # ---------------------------
    def start_polling_conversation(self):
        if not self.suppress_polling:
            self.cancel_polling()
            self.poll_conversation()

    def poll_conversation(self):
        if self.session_username and self.current_convo and not self.suppress_polling:
            req = chat_pb2.PollConvoRequest(
                username=self.session_username,
                hashed_password=self.session_hash,
                other_user=self.current_convo
            )
            threading.Thread(target=self._poll_thread, args=(req,)).start()
        self.polling_job = self.root.after(2000, self.poll_conversation)

    def _poll_thread(self, req):
        resp = stub.PollConvo(req)
        self.root.after(0, self.handle_poll_response, resp)

    def handle_poll_response(self, response):
        if self.suppress_polling:
            return
        if response.status.startswith("OK"):
            if response.message.startswith("No new messages"):
                # do nothing
                return
            # otherwise, append the newly arrived messages
            for msg in response.messages:
                existing_ids = {
                    self.chat_tree.item(item)["values"][0]
                    for item in self.chat_tree.get_children()
                }
                if msg.id not in existing_ids:
                    self.chat_tree.insert("", tk.END, values=(msg.id, msg.sender, msg.content))
            self.chat_tree.yview_moveto(1)
            self.refresh_conversations()
        else:
            # Possibly an error like "Account does not exist" or "Authentication failed"
            print("POLL_CONVO error:", response.message)

    def cancel_polling(self):
        if self.polling_job:
            self.root.after_cancel(self.polling_job)
            self.polling_job = None

    # ---------------------------
    #  Full message popup
    # ---------------------------
    def show_full_message(self, event):
        selected = self.chat_tree.selection()
        if not selected:
            return
        item = self.chat_tree.item(selected[0])
        values = item["values"]
        if len(values) < 3:
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
