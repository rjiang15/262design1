#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSON Server for account and messaging functionalities.
This version uses JSON messages over the wire.
All commands and responses are JSON objects.
The supported commands (sent as JSON) include:
  - Account management: CREATE, LOGIN, DELETE, LOGOUT
  - Messaging: SEND, READ, DELETE_MSG, MARK_READ, READ_CONVO, READ_FULL_CONVO, POLL_CONVO
  - Listing: LIST, LIST_CONVERSATIONS
  - Debug: SHOW_DB

For example, to create an account, the client sends:
  {"command": "CREATE", "username": "bob", "hashed_password": "..."}

Responses are returned as JSON, for example:
  {"status": "OK", "message": "Account created"}
"""

import argparse
import socket
import selectors
import types
import sqlite3
import os
import json

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Start the JSON server.")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Host IP to bind the server (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Port to bind the server (default: 54400)")
args = parser.parse_args()
HOST = args.host
PORT = args.port

sel = selectors.DefaultSelector()

# Use a separate database file for the JSON server.
db_path = os.path.join(os.path.dirname(__file__), "server_json.db")
conn = sqlite3.connect(db_path, check_same_thread=False)
cursor = conn.cursor()

# Create tables if they don't exist.
cursor.execute('''
CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    logged_in INTEGER DEFAULT 0
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    content TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    FOREIGN KEY(recipient) REFERENCES accounts(username)
)
''')
conn.commit()

def display_db_contents():
    """Helper function to display all contents of the database."""
    print("----- Database Contents -----")
    print("Accounts:")
    for row in cursor.execute("SELECT * FROM accounts"):
        print(row)
    print("\nMessages:")
    for row in cursor.execute("SELECT * FROM messages"):
        print(row)
    print("----- End of Database Contents -----")

def process_command_json(cmd):
    """Processes a command (as a dict) and returns a dict response."""
    command = cmd.get("command", "").upper()
    resp = {}
    try:
        if command == "SHOW_DB":
            display_db_contents()
            resp["status"] = "OK"
            resp["message"] = "Database contents displayed on server console"
        
        elif command == "LIST":
            pattern = cmd.get("pattern", "%")
            if "%" not in pattern:
                pattern = "%" + pattern + "%"
            offset = int(cmd.get("offset", 0))
            limit = int(cmd.get("limit", 10))
            cursor.execute("SELECT username FROM accounts WHERE username LIKE ? LIMIT ? OFFSET ?", (pattern, limit, offset))
            rows = cursor.fetchall()
            if not rows:
                resp["status"] = "OK"
                resp["message"] = "No accounts found"
            else:
                cursor.execute("SELECT COUNT(*) FROM accounts WHERE username LIKE ?", (pattern,))
                total = cursor.fetchone()[0]
                accounts_list = [row[0] for row in rows]
                resp["status"] = "OK"
                resp["total_accounts"] = total
                resp["accounts"] = accounts_list
        
        elif command == "LIST_CONVERSATIONS":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Incorrect password"
            else:
                cursor.execute("""
                    SELECT partner FROM (
                        SELECT sender as partner FROM messages WHERE recipient = ?
                        UNION
                        SELECT recipient as partner FROM messages WHERE sender = ? AND recipient <> ?
                    ) ORDER BY partner ASC
                """, (username, username, username))
                partners = cursor.fetchall()
                valid_partners = []
                total_unread = 0
                conversations = []
                for (partner,) in partners:
                    cursor.execute("SELECT COUNT(*) FROM accounts WHERE username = ?", (partner,))
                    if cursor.fetchone()[0] == 0:
                        continue
                    valid_partners.append(partner)
                    cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender = ? AND read = 0", (username, partner))
                    unread = cursor.fetchone()[0]
                    total_unread += unread
                    cursor.execute("""
                        SELECT sender, content FROM messages
                        WHERE (recipient = ? AND sender = ?) OR (recipient = ? AND sender = ?)
                        ORDER BY id DESC LIMIT 1
                    """, (username, partner, partner, username))
                    last = cursor.fetchone()
                    last_message = f"{last[0]}: {last[1]}" if last else ""
                    conversations.append({"partner": partner, "unread": unread, "last": last_message})
                resp["status"] = "OK"
                resp["total_unread"] = total_unread
                resp["message"] = f"Total unread messages: {total_unread}"
                resp["conversations"] = conversations
        
        elif command == "READ_CONVO":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            other_user = cmd["other_user"]
            n = int(cmd["n"])
            cursor.execute("""
                SELECT COUNT(*) FROM messages
                WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                  AND read = 0
                ORDER BY id ASC
            """, (username, other_user, other_user, username))
            unread_count = cursor.fetchone()[0]
            if unread_count > 0:
                cursor.execute("""
                    SELECT id, sender, content FROM messages
                    WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                      AND read = 0
                    ORDER BY id ASC LIMIT ?
                """, (username, other_user, other_user, username, n))
            else:
                cursor.execute("""
                    SELECT id, sender, content FROM messages
                    WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                    ORDER BY id ASC LIMIT ?
                """, (username, other_user, other_user, username, n))
            messages = cursor.fetchall()
            if not messages:
                resp["status"] = "OK"
                resp["message"] = f"No messages in conversation with {other_user}"
            else:
                msgs = []
                msg_ids = []
                for msg in messages:
                    msg_id, sender, content = msg
                    msgs.append({"id": msg_id, "sender": sender, "content": content})
                    msg_ids.append(msg_id)
                    print(f"Message {msg_id} read by {username}")
                if msg_ids:
                    cursor.execute("UPDATE messages SET read = 1 WHERE id IN ({seq}) AND recipient = ?".format(seq=",".join(['?']*len(msg_ids))), (*msg_ids, username))
                    conn.commit()
                resp["status"] = "OK"
                resp["messages"] = msgs
        
        elif command == "READ_FULL_CONVO":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            other_user = cmd["other_user"]
            n = int(cmd["n"])
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Authentication failed"
            else:
                cursor.execute("""
                    SELECT id, sender, content FROM messages
                    WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                    ORDER BY id ASC LIMIT ?
                """, (username, other_user, other_user, username, n))
                messages = cursor.fetchall()
                if not messages:
                    resp["status"] = "OK"
                    resp["message"] = f"No messages in conversation with {other_user}"
                else:
                    msgs = []
                    for msg in messages:
                        msg_id, sender, content = msg
                        msgs.append({"id": msg_id, "sender": sender, "content": content})
                    resp["status"] = "OK"
                    resp["messages"] = msgs
        
        elif command == "POLL_CONVO":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            other_user = cmd["other_user"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Authentication failed"
            else:
                cursor.execute("""
                    SELECT id, sender, content FROM messages
                    WHERE recipient = ? AND sender = ? AND read = 0
                    ORDER BY id ASC
                """, (username, other_user))
                messages = cursor.fetchall()
                if not messages:
                    resp["status"] = "OK"
                    resp["message"] = "No new messages"
                else:
                    msgs = []
                    msg_ids = []
                    for msg in messages:
                        msg_id, sender, content = msg
                        msgs.append({"id": msg_id, "sender": sender, "content": content})
                        msg_ids.append(msg_id)
                        print(f"Message {msg_id} read by {username} (via poll)")
                    if msg_ids:
                        cursor.execute("UPDATE messages SET read = 1 WHERE id IN ({seq})".format(seq=",".join(['?']*len(msg_ids))), msg_ids)
                        conn.commit()
                    resp["status"] = "OK"
                    resp["messages"] = msgs
        
        elif command == "CREATE":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                resp["status"] = "ERROR"
                resp["message"] = "Account already exists"
            else:
                # Remove any lingering messages for this username.
                cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (username, username))
                cursor.execute("INSERT INTO accounts (username, password, logged_in) VALUES (?, ?, 0)", (username, hashed_password))
                conn.commit()
                resp["status"] = "OK"
                resp["message"] = "Account created"
        
        elif command == "LOGIN":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Incorrect password"
            else:
                cursor.execute("UPDATE accounts SET logged_in = 1 WHERE username = ?", (username,))
                conn.commit()
                cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0", (username,))
                count = cursor.fetchone()[0]
                print(f"User {username} logged in at {HOST}:{PORT}")
                resp["status"] = "OK"
                resp["message"] = f"Login successful, unread messages: {count}"
        
        elif command == "LOGOUT":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Incorrect password"
            else:
                cursor.execute("UPDATE accounts SET logged_in = 0 WHERE username = ?", (username,))
                conn.commit()
                print(f"User {username} logged out")
                resp["status"] = "OK"
                resp["message"] = "Logged out"
        
        elif command == "DELETE":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Incorrect password"
            else:
                cursor.execute("DELETE FROM accounts WHERE username = ?", (username,))
                cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (username, username))
                conn.commit()
                resp["status"] = "OK"
                resp["message"] = "Account deleted"
        
        elif command == "SEND":
            sender = cmd["sender"]
            hashed_password = cmd["hashed_password"]
            recipient = cmd["recipient"]
            message = cmd["message"]
            if len(message) > 256:
                resp["status"] = "ERROR"
                resp["message"] = "Message too long. Maximum allowed is 256 characters."
            else:
                cursor.execute("SELECT password FROM accounts WHERE username = ?", (sender,))
                row = cursor.fetchone()
                if row is None:
                    resp["status"] = "ERROR"
                    resp["message"] = "Sender account does not exist"
                elif row[0] != hashed_password:
                    resp["status"] = "ERROR"
                    resp["message"] = "Sender authentication failed"
                else:
                    cursor.execute("SELECT * FROM accounts WHERE username = ?", (recipient,))
                    if cursor.fetchone() is None:
                        resp["status"] = "ERROR"
                        resp["message"] = "Recipient account does not exist"
                    else:
                        cursor.execute("INSERT INTO messages (recipient, sender, content, read) VALUES (?, ?, ?, 0)", (recipient, sender, message))
                        conn.commit()
                        msg_id = cursor.lastrowid
                        print(f"Message sent: from {sender} to {recipient}, id {msg_id}")
                        resp["status"] = "OK"
                        resp["message"] = f"Message sent with id {msg_id}"
        
        elif command == "READ":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            n = int(cmd["n"])
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Authentication failed"
            else:
                cursor.execute("SELECT id, sender, content FROM messages WHERE recipient = ? ORDER BY id ASC LIMIT ?", (username, n))
                messages = cursor.fetchall()
                if not messages:
                    resp["status"] = "OK"
                    resp["message"] = "No messages"
                else:
                    msgs = []
                    msg_ids = []
                    for msg in messages:
                        msg_id, sender, content = msg
                        msgs.append({"id": msg_id, "sender": sender, "content": content})
                        msg_ids.append(msg_id)
                        print(f"Message {msg_id} read by {username}")
                    cursor.execute("UPDATE messages SET read = 1 WHERE id IN ({seq})".format(seq=",".join(['?']*len(msg_ids))), msg_ids)
                    conn.commit()
                    resp["status"] = "OK"
                    resp["messages"] = msgs
        
        elif command == "DELETE_MSG":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            target = cmd["target"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Authentication failed"
            else:
                if target.upper() == "ALL":
                    cursor.execute("SELECT COUNT(*) FROM messages WHERE (recipient = ? OR sender = ?)", (username, username))
                    count = cursor.fetchone()[0]
                    cursor.execute("DELETE FROM messages WHERE (recipient = ? OR sender = ?)", (username, username))
                    conn.commit()
                    resp["status"] = "OK"
                    resp["message"] = f"Deleted all messages ({count} messages)"
                else:
                    try:
                        id_list = [int(x.strip()) for x in target.split(",")]
                    except ValueError:
                        resp["status"] = "ERROR"
                        resp["message"] = "All message IDs must be integers or ALL"
                        return resp
                    for msg_id in id_list:
                        cursor.execute("SELECT * FROM messages WHERE id = ? AND (recipient = ? OR sender = ?)", (msg_id, username, username))
                        if cursor.fetchone() is None:
                            resp["status"] = "ERROR"
                            resp["message"] = f"Message id {msg_id} not found or not authorized to delete"
                            return resp
                    cursor.execute("DELETE FROM messages WHERE id IN ({seq})".format(seq=",".join(['?']*len(id_list))), id_list)
                    conn.commit()
                    resp["status"] = "OK"
                    resp["message"] = f"Deleted message ids {','.join(map(str, id_list))}"
        
        elif command == "MARK_READ":
            username = cmd["username"]
            hashed_password = cmd["hashed_password"]
            target = cmd["target"]
            cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row is None:
                resp["status"] = "ERROR"
                resp["message"] = "Account does not exist"
            elif row[0] != hashed_password:
                resp["status"] = "ERROR"
                resp["message"] = "Authentication failed"
            else:
                if target.upper() == "ALL":
                    cursor.execute("UPDATE messages SET read = 1 WHERE recipient = ? AND read = 0", (username,))
                    conn.commit()
                    resp["status"] = "OK"
                    resp["message"] = "Marked all messages as read"
                else:
                    try:
                        msg_id = int(target)
                    except ValueError:
                        resp["status"] = "ERROR"
                        resp["message"] = "msg_id must be an integer or ALL"
                        return resp
                    cursor.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (msg_id, username))
                    if cursor.fetchone() is None:
                        resp["status"] = "ERROR"
                        resp["message"] = "Message id not found"
                    else:
                        cursor.execute("UPDATE messages SET read = 1 WHERE id = ?", (msg_id,))
                        conn.commit()
                        print(f"Message {msg_id} marked as read by {username}")
                        resp["status"] = "OK"
                        resp["message"] = f"Marked message id {msg_id} as read"
        
        else:
            resp["status"] = "ERROR"
            resp["message"] = "Unknown command"
    except Exception as e:
        resp["status"] = "ERROR"
        resp["message"] = str(e)
    return resp

def accept_wrapper(sock):
    # Do not print accepted connection messages.
    conn_sock, addr = sock.accept()
    conn_sock.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn_sock, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(4096)
        if recv_data:
            data.inb += recv_data
            # Each JSON message is delimited by newline.
            while b'\n' in data.inb:
                line, data.inb = data.inb.split(b'\n', 1)
                try:
                    cmd = json.loads(line.decode('utf-8').strip())
                except Exception as e:
                    response = {"status": "ERROR", "message": f"JSON parse error: {str(e)}"}
                    data.outb += (json.dumps(response) + "\n").encode("utf-8")
                    continue
                response = process_command_json(cmd)
                data.outb += (json.dumps(response) + "\n").encode("utf-8")
        else:
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]

if __name__ == "__main__":
    print(f"Listening on {HOST}:{PORT}")
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((HOST, PORT))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Keyboard interrupt, exiting")
    finally:
        sel.close()
        conn.close()
