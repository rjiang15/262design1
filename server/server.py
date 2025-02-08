#!/usr/bin/evn python3
# -*- coding: utf-8 -*-
"""
Initial Functions from @waldo
Design Exercise 1 for CS 2620 S25

"""

import socket
import selectors
import types

sel = selectors.DefaultSelector()

HOST = "127.0.0.1"
PORT = 54400

# Global in-memory storage for accounts.
# Each account is a dictionary with a hashed password and an unread message count.
accounts = {}  # Format: { username: {"password": hashed_password, "unread": 0} }

# PHASE 2
def process_command(command):
    """Parses and processes a command string and returns a response."""
    tokens = command.split()
    if not tokens:
        return "ERROR: Empty command"
    
    cmd = tokens[0].upper()
    
    if cmd == "CREATE":
        if len(tokens) != 3:
            return "ERROR: Usage: CREATE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        if username in accounts:
            return "ERROR: Account already exists"
        accounts[username] = {"password": hashed_password, "unread": 0}
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
    
    else:
        return "ERROR: Unknown command"

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Accept the connection from the client
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Read up to 1024 bytes
        if recv_data:
            data.inb += recv_data
            # Process complete lines (commands end with a newline)
            while b'\n' in data.inb:
                line, data.inb = data.inb.split(b'\n', 1)
                command = line.decode('utf-8').strip()
                if command:  # If the command is not empty
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