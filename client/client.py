#!/usr/bin/evn python3
# -*- coding: utf-8 -*-
"""
Initial Functions from @waldo
Design Exercise 1 for CS 2620 S25

"""

import socket
import hashlib

HOST = "127.0.0.1"
PORT = 54400

def hash_password(password):
    """Return the SHA-256 hash of the given password as a hexadecimal string."""
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected to server.")
        
        while True:
            print("\nSelect an option:")
            print("1) Create Account")
            print("2) Login")
            print("3) Delete Account")
            print("4) Exit")
            choice = input("Enter your choice: ").strip()
            
            if choice == "4":
                break
            
            if choice not in {"1", "2", "3"}:
                print("Invalid choice, please try again.")
                continue
            
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            hashed = hash_password(password)
            
            if choice == "1":
                command = f"CREATE {username} {hashed}"
            elif choice == "2":
                command = f"LOGIN {username} {hashed}"
            elif choice == "3":
                command = f"DELETE {username} {hashed}"
            
            # Send command with newline termination
            s.sendall((command + "\n").encode('utf-8'))
            response = s.recv(1024).decode('utf-8')
            print("Server response:", response.strip())

if __name__ == "__main__":
    main()