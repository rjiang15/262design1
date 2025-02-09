#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server for account and messaging functionalities (Phase 3.5, Phase 4 and Phase 4.5).
Supports the following commands (each terminated with a newline):

  Account management:
    CREATE username hashed_password
    LOGIN username hashed_password
    DELETE username hashed_password
    LOGOUT username hashed_password

  Messaging:
    SEND sender hashed_password recipient message...
    READ username hashed_password n
    DELETE_MSG username hashed_password <msg_id|ALL>
    MARK_READ username hashed_password <msg_id|ALL>
    READ_CONVO username hashed_password other_user n

  Listing:
    LIST [pattern] [offset] [limit]
    LIST_CONVERSATIONS username hashed_password

  Debugging:
    SHOW_DB   -- Display the contents of the database on the server console

Messages are stored in a sqlite3 database.
Accounts include a 'logged_in' flag, and each message has a 'read' flag.
"""

import argparse
import socket
import selectors
import types
import sqlite3
import os

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Start the server.")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Host IP to bind the server (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Port to bind the server (default: 54400)")
args = parser.parse_args()
HOST = args.host
PORT = args.port

sel = selectors.DefaultSelector()

# Build the path to the database file so that it lives in the same folder as server.py.
db_path = os.path.join(os.path.dirname(__file__), "server.db")
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

def process_command(command):
    """Parses and processes a command string and returns a response."""
    tokens = command.split()
    if not tokens:
        return "ERROR: Empty command"
    
    cmd = tokens[0].upper()
    
    # DEBUG COMMAND: SHOW_DB
    if cmd == "SHOW_DB":
        display_db_contents()
        return "OK: Database contents displayed on server console"
    
    # LISTING COMMAND: LIST [pattern] [offset] [limit]
    elif cmd == "LIST":
        pattern = "%"
        offset = 0
        limit = 10
        if len(tokens) > 1:
            pattern = tokens[1]
            if "%" not in pattern:
                pattern = "%" + pattern + "%"
        if len(tokens) > 2:
            try:
                offset = int(tokens[2])
            except ValueError:
                return "ERROR: offset must be an integer"
        if len(tokens) > 3:
            try:
                limit = int(tokens[3])
            except ValueError:
                return "ERROR: limit must be an integer"
        cursor.execute("SELECT username FROM accounts WHERE username LIKE ? LIMIT ? OFFSET ?", (pattern, limit, offset))
        rows = cursor.fetchall()
        if not rows:
            return "OK: No accounts found"
        cursor.execute("SELECT COUNT(*) FROM accounts WHERE username LIKE ?", (pattern,))
        total = cursor.fetchone()[0]
        response_lines = [f"Total accounts matching: {total}", "Accounts:"]
        for row in rows:
            response_lines.append(row[0])
        return "\n".join(response_lines)
    
    # LIST_CONVERSATIONS command: LIST_CONVERSATIONS username hashed_password
    elif cmd == "LIST_CONVERSATIONS":
        if len(tokens) != 3:
            return "ERROR: Usage: LIST_CONVERSATIONS username hashed_password"
        username = tokens[1]
        hashed_password = tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Incorrect password"
        # Retrieve distinct conversation partners:
        cursor.execute("""
            SELECT partner FROM (
                SELECT sender as partner FROM messages WHERE recipient = ?
                UNION
                SELECT recipient as partner FROM messages WHERE sender = ? AND recipient <> ?
            ) ORDER BY partner ASC
        """, (username, username, username))
        partners = cursor.fetchall()
        if not partners:
            return "OK: No conversations"
        response_lines = []
        total_unread = 0
        for (partner,) in partners:
            cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender = ? AND read = 0", (username, partner))
            unread = cursor.fetchone()[0]
            total_unread += unread
            cursor.execute("""
                SELECT sender, content FROM messages
                WHERE (recipient = ? AND sender = ?) OR (recipient = ? AND sender = ?)
                ORDER BY id DESC LIMIT 1
            """, (username, partner, partner, username))
            last = cursor.fetchone()
            if last:
                last_message = f"{last[0]}: {last[1]}"
            else:
                last_message = ""
            response_lines.append(f"Partner: {partner}, Unread: {unread}, Last: {last_message}")
        response_lines.insert(0, f"Total unread messages: {total_unread}")
        return "\n".join(response_lines)
    
    # READ_CONVO command: READ_CONVO username hashed_password other_user n
    elif cmd == "READ_CONVO":
        if len(tokens) != 5:
            return "ERROR: Usage: READ_CONVO username hashed_password other_user n"
        username = tokens[1]
        hashed_password = tokens[2]
        other_user = tokens[3]
        try:
            n = int(tokens[4])
        except ValueError:
            return "ERROR: n must be an integer"
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Authentication failed"
        cursor.execute("""
            SELECT id, sender, content FROM messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY id ASC LIMIT ?
        """, (username, other_user, other_user, username, n))
        messages = cursor.fetchall()
        if not messages:
            return f"OK: No messages in conversation with {other_user}"
        response_lines = []
        msg_ids = []
        for msg in messages:
            msg_id, sender, content = msg
            response_lines.append(f"ID: {msg_id}, From: {sender}, Message: {content}")
            msg_ids.append(msg_id)
        if msg_ids:
            cursor.execute("UPDATE messages SET read = 1 WHERE id IN ({seq}) AND recipient = ?".format(seq=','.join(['?']*len(msg_ids))), (*msg_ids, username))
            conn.commit()
        return "\n".join(response_lines)
    
    # ACCOUNT MANAGEMENT COMMANDS
    elif cmd == "CREATE":
        if len(tokens) != 3:
            return "ERROR: Usage: CREATE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            return "ERROR: Account already exists"
        cursor.execute("INSERT INTO accounts (username, password, logged_in) VALUES (?, ?, 0)", (username, hashed_password))
        conn.commit()
        return "OK: Account created"
    
    elif cmd == "LOGIN":
        if len(tokens) != 3:
            return "ERROR: Usage: LOGIN username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Incorrect password"
        cursor.execute("UPDATE accounts SET logged_in = 1 WHERE username = ?", (username,))
        conn.commit()
        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0", (username,))
        count = cursor.fetchone()[0]
        return f"OK: Login successful, unread messages: {count}"
    
    elif cmd == "LOGOUT":
        if len(tokens) != 3:
            return "ERROR: Usage: LOGOUT username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Incorrect password"
        cursor.execute("UPDATE accounts SET logged_in = 0 WHERE username = ?", (username,))
        conn.commit()
        return "OK: Logged out"
    
    elif cmd == "DELETE":
        if len(tokens) != 3:
            return "ERROR: Usage: DELETE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Incorrect password"
        cursor.execute("DELETE FROM accounts WHERE username = ?", (username,))
        cursor.execute("DELETE FROM messages WHERE recipient = ?", (username,))
        conn.commit()
        return "OK: Account deleted"
    
    # MESSAGING COMMANDS
    elif cmd == "SEND":
        if len(tokens) < 5:
            return "ERROR: Usage: SEND sender hashed_password recipient message"
        sender = tokens[1]
        hashed_password = tokens[2]
        recipient = tokens[3]
        message = " ".join(tokens[4:])
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (sender,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Sender account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Sender authentication failed"
        cursor.execute("SELECT * FROM accounts WHERE username = ?", (recipient,))
        if cursor.fetchone() is None:
            return "ERROR: Recipient account does not exist"
        cursor.execute("INSERT INTO messages (recipient, sender, content, read) VALUES (?, ?, ?, 0)", (recipient, sender, message))
        conn.commit()
        msg_id = cursor.lastrowid
        return f"OK: Message sent with id {msg_id}"
    
    elif cmd == "READ":
        if len(tokens) != 4:
            return "ERROR: Usage: READ username hashed_password n"
        username = tokens[1]
        hashed_password = tokens[2]
        try:
            n = int(tokens[3])
        except ValueError:
            return "ERROR: n must be an integer"
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Authentication failed"
        cursor.execute("SELECT id, sender, content FROM messages WHERE recipient = ? ORDER BY id ASC LIMIT ?", (username, n))
        messages = cursor.fetchall()
        if not messages:
            return "OK: No messages"
        response_lines = []
        msg_ids = []
        for msg in messages:
            msg_id, sender, content = msg
            response_lines.append(f"ID: {msg_id}, From: {sender}, Message: {content}")
            msg_ids.append(msg_id)
        cursor.execute("UPDATE messages SET read = 1 WHERE id IN ({seq})".format(seq=','.join(['?']*len(msg_ids))), msg_ids)
        conn.commit()
        return "\n".join(response_lines)
    
    elif cmd == "DELETE_MSG":
        if len(tokens) != 4:
            return "ERROR: Usage: DELETE_MSG username hashed_password <msg_id|ALL>"
        username = tokens[1]
        hashed_password = tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Authentication failed"
        target = tokens[3]
        if target.upper() == "ALL":
            cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ?", (username,))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM messages WHERE recipient = ?", (username,))
            conn.commit()
            return f"OK: Deleted all messages ({count} messages)"
        else:
            try:
                msg_id = int(target)
            except ValueError:
                return "ERROR: msg_id must be an integer or ALL"
            cursor.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (msg_id, username))
            if cursor.fetchone() is None:
                return "ERROR: Message id not found"
            cursor.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
            conn.commit()
            return f"OK: Deleted message id {msg_id}"
    
    elif cmd == "MARK_READ":
        if len(tokens) != 4:
            return "ERROR: Usage: MARK_READ username hashed_password <msg_id|ALL>"
        username = tokens[1]
        hashed_password = tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Authentication failed"
        target = tokens[3]
        if target.upper() == "ALL":
            cursor.execute("UPDATE messages SET read = 1 WHERE recipient = ? AND read = 0", (username,))
            conn.commit()
            return "OK: Marked all messages as read"
        else:
            try:
                msg_id = int(target)
            except ValueError:
                return "ERROR: msg_id must be an integer or ALL"
            cursor.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (msg_id, username))
            if cursor.fetchone() is None:
                return "ERROR: Message id not found"
            cursor.execute("UPDATE messages SET read = 1 WHERE id = ?", (msg_id,))
            conn.commit()
            return f"OK: Marked message id {msg_id} as read"
    
    else:
        return "ERROR: Unknown command"

def accept_wrapper(sock):
    conn_sock, addr = sock.accept()  # Accept the connection from the client.
    print(f"Accepted connection from {addr}")
    conn_sock.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn_sock, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            data.inb += recv_data
            while b'\n' in data.inb:
                line, data.inb = data.inb.split(b'\n', 1)
                command = line.decode('utf-8').strip()
                if command:
                    response = process_command(command)
                    data.outb += (response + "\n").encode('utf-8')
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if data.outb:
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]

if __name__ == "__main__":
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((HOST, PORT))
    lsock.listen()
    print("Listening on", (HOST, PORT))
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
