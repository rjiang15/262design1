#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client for account and messaging functionalities (Phase 3.5 and Phase 4).
Provides a menu for account management, messaging, and listing accounts.
Passwords are hashed (SHA-256) before being sent.
After a successful login, session credentials are stored for subsequent commands.
"""

import socket
import hashlib

HOST = "127.0.0.1"
PORT = 54400

def hash_password(password):
    """Return the SHA-256 hash of the given password as a hexadecimal string."""
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    session_username = None
    session_hash = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected to server.")

        while True:
            print("\nSelect an option:")
            print("1) Create Account")
            print("2) Login")
            print("3) Delete Account")
            print("4) Send Message")
            print("5) Read Messages")
            print("6) Delete Message")
            print("7) Mark Message as Read")
            print("8) Logout")
            print("9) Exit")
            print("10) Show Database (Debug)")
            print("11) List Accounts")  # New option for listing accounts
            choice = input("Enter your choice: ").strip()

            if choice == "9":
                break

            # CREATE ACCOUNT
            if choice == "1":
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                hashed = hash_password(password)
                command = f"CREATE {username} {hashed}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())

            # LOGIN
            elif choice == "2":
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                hashed = hash_password(password)
                command = f"LOGIN {username} {hashed}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())
                if response.startswith("OK:"):
                    session_username = username
                    session_hash = hashed

            # DELETE ACCOUNT
            elif choice == "3":
                if session_username is None:
                    username = input("Enter username: ").strip()
                    password = input("Enter password: ").strip()
                    hashed = hash_password(password)
                else:
                    username = session_username
                    hashed = session_hash
                command = f"DELETE {username} {hashed}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())
                if response.startswith("OK:") and session_username == username:
                    session_username = None
                    session_hash = None

            # SEND MESSAGE
            elif choice == "4":
                if session_username is None:
                    print("Please login first.")
                    continue
                recipient = input("Enter recipient username: ").strip()
                message = input("Enter message: ").strip()
                command = f"SEND {session_username} {session_hash} {recipient} {message}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())

            # READ MESSAGES
            elif choice == "5":
                if session_username is None:
                    print("Please login first.")
                    continue
                num = input("Enter number of messages to read: ").strip()
                command = f"READ {session_username} {session_hash} {num}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(4096).decode('utf-8')
                print("Server response:\n", response.strip())

            # DELETE MESSAGE
            elif choice == "6":
                if session_username is None:
                    print("Please login first.")
                    continue
                msg_id = input("Enter message ID to delete or ALL to delete all: ").strip()
                command = f"DELETE_MSG {session_username} {session_hash} {msg_id}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())

            # MARK MESSAGE AS READ
            elif choice == "7":
                if session_username is None:
                    print("Please login first.")
                    continue
                target = input("Enter message ID to mark as read or ALL to mark all as read: ").strip()
                command = f"MARK_READ {session_username} {session_hash} {target}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())

            # LOGOUT
            elif choice == "8":
                if session_username is None:
                    print("Not logged in.")
                    continue
                command = f"LOGOUT {session_username} {session_hash}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())
                if response.startswith("OK:"):
                    session_username = None
                    session_hash = None

            # SHOW DATABASE (Debug)
            elif choice == "10":
                command = "SHOW_DB"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(2048).decode('utf-8')
                print("Server response:", response.strip())

            # LIST ACCOUNTS
            elif choice == "11":
                # Prompt for optional filtering and pagination parameters.
                pattern = input("Enter a pattern to filter accounts (leave blank for all): ").strip()
                if not pattern:
                    pattern = "%"
                offset = input("Enter offset (default 0): ").strip()
                if not offset:
                    offset = "0"
                limit = input("Enter limit (default 10): ").strip()
                if not limit:
                    limit = "10"
                command = f"LIST {pattern} {offset} {limit}"
                s.sendall((command + "\n").encode('utf-8'))
                response = s.recv(4096).decode('utf-8')
                print("Server response:\n", response.strip())

            else:
                print("Invalid choice.")

if __name__ == "__main__":
    main()
