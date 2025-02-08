#!/usr/bin/evn python3
# -*- coding: utf-8 -*-
"""
Initial Functions from @waldo
Design Exercise 1 for CS 2620 S25

"""
import socket

HOST = "127.0.0.1"
PORT = 54400

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        message = input("Enter a message to send to the server: ")
        if message == "exit":
            break
        message = message.encode("utf-8")
        s.sendall(message)
        data = s.recv(1024)
        data = data.decode("utf-8")
        print(f"Received: {data}")
