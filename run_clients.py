#!/usr/bin/env python3
import subprocess
import time

num_clients = 5  # Adjust as needed
clients = []

# Launch multiple client processes
for i in range(num_clients):
    proc = subprocess.Popen(["python", "client/client.py"])
    clients.append(proc)
    time.sleep(0.5)  # Small delay between launching clients

# Optionally wait for all clients to finish
for proc in clients:
    proc.wait()
