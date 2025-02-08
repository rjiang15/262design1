#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server for account and messaging functionalities (Phase 3).
Supports the following commands (each terminated with a newline):
  Account management:
    CREATE username hashed_password
    LOGIN username hashed_password
    DELETE username hashed_password

  Messaging:
    SEND sender hashed_password recipient message...
    READ username hashed_password n
    DELETE_MSG username hashed_password <msg_id|ALL>
    
Messages are stored offline in each account and include an auto-incremented id, sender, and content.
"""

import socket
import selectors
import types

sel = selectors.DefaultSelector()
HOST = "127.0.0.1"
PORT = 54400

# Global in-memory storage for accounts.
# Each account is a dictionary with keys:
#   password       : the hashed password,
#   unread         : number of unread messages,
#   messages       : dictionary of messages (keyed by msg id),
#   next_msg_id    : integer for the next message id.
accounts = {}  # Format: { username: {"password": hashed_password, "unread": 0, "messages": {}, "next_msg_id": 1} }

def process_command(command):
    """Parses and processes a command string and returns a response."""
    tokens = command.split()
    if not tokens:
        return "ERROR: Empty command"
    
    cmd = tokens[0].upper()
    
    # ACCOUNT MANAGEMENT COMMANDS
    if cmd == "CREATE":
        if len(tokens) != 3:
            return "ERROR: Usage: CREATE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        if username in accounts:
            return "ERROR: Account already exists"
        accounts[username] = {
            "password": hashed_password,
            "unread": 0,
            "messages": {},
            "next_msg_id": 1
        }
        return "OK: Account created"
    
    elif cmd == "LOGIN":
        if len(tokens) != 3:
            return "ERROR: Usage: LOGIN username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        if username not in accounts:
            return "ERROR: Account does not exist"
        if accounts[username]["password"] != hashed_password:
            return "ERROR: Incorrect password"
        return f"OK: Login successful, unread messages: {accounts[username]['unread']}"
    
    elif cmd == "DELETE":
        if len(tokens) != 3:
            return "ERROR: Usage: DELETE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        if username not in accounts:
            return "ERROR: Account does not exist"
        if accounts[username]["password"] != hashed_password:
            return "ERROR: Incorrect password"
        del accounts[username]
        return "OK: Account deleted"
    
    # MESSAGING COMMANDS
    elif cmd == "SEND":
        # Format: SEND sender hashed_password recipient message...
        if len(tokens) < 5:
            return "ERROR: Usage: SEND sender hashed_password recipient message"
        sender = tokens[1]
        hashed_password = tokens[2]
        recipient = tokens[3]
        message = " ".join(tokens[4:])
        # Validate sender
        if sender not in accounts:
            return "ERROR: Sender account does not exist"
        if accounts[sender]["password"] != hashed_password:
            return "ERROR: Sender authentication failed"
        # Validate recipient
        if recipient not in accounts:
            return "ERROR: Recipient account does not exist"
        # Create and store the message in recipient's mailbox.
        msg_id = accounts[recipient]["next_msg_id"]
        accounts[recipient]["next_msg_id"] += 1
        msg = {"id": msg_id, "sender": sender, "content": message}
        accounts[recipient]["messages"][msg_id] = msg
        accounts[recipient]["unread"] += 1
        return f"OK: Message sent with id {msg_id}"
    
    elif cmd == "READ":
        # Format: READ username hashed_password n
        if len(tokens) != 4:
            return "ERROR: Usage: READ username hashed_password n"
        username = tokens[1]
        hashed_password = tokens[2]
        try:
            n = int(tokens[3])
        except ValueError:
            return "ERROR: n must be an integer"
        if username not in accounts:
            return "ERROR: Account does not exist"
        if accounts[username]["password"] != hashed_password:
            return "ERROR: Authentication failed"
        # Retrieve messages sorted by id
        messages = sorted(accounts[username]["messages"].values(), key=lambda m: m["id"])
        if not messages:
            return "OK: No messages"
        selected = messages[:n]
        response_lines = []
        for msg in selected:
            response_lines.append(f"ID: {msg['id']}, From: {msg['sender']}, Message: {msg['content']}")
        return "\n".join(response_lines)
    
    elif cmd == "DELETE_MSG":
        # Format: DELETE_MSG username hashed_password <msg_id|ALL>
        if len(tokens) != 4:
            return "ERROR: Usage: DELETE_MSG username hashed_password <msg_id|ALL>"
        username = tokens[1]
        hashed_password = tokens[2]
        if username not in accounts:
            return "ERROR: Account does not exist"
        if accounts[username]["password"] != hashed_password:
            return "ERROR: Authentication failed"
        target = tokens[3]
        if target.upper() == "ALL":
            count = len(accounts[username]["messages"])
            accounts[username]["messages"].clear()
            accounts[username]["unread"] = 0
            return f"OK: Deleted all messages ({count} messages)"
        else:
            try:
                msg_id = int(target)
            except ValueError:
                return "ERROR: msg_id must be an integer or ALL"
            if msg_id not in accounts[username]["messages"]:
                return "ERROR: Message id not found"
            del accounts[username]["messages"][msg_id]
            # Adjust unread count if needed.
            accounts[username]["unread"] = max(0, accounts[username]["unread"] - 1)
            return f"OK: Deleted message id {msg_id}"
    
    else:
        return "ERROR: Unknown command"

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Accept the connection from the client.
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Read up to 1024 bytes.
        if recv_data:
            data.inb += recv_data
            # Process complete lines (commands end with a newline).
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
