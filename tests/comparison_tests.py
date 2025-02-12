#!/usr/bin/env python3
import argparse
import socket
import json
import time
import threading
import sys
import re

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Run efficiency and scaling tests for either custom or JSON protocol.")
parser.add_argument("--protocol", type=str, choices=["json", "custom"], default="custom",
                    help="Protocol to test: 'json' or 'custom' (default: custom)")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port (default: 54400)")
args = parser.parse_args()

HOST = args.host
PORT = args.port
protocol = args.protocol

# Global counters for bytes sent and received (client side)
total_bytes_sent = 0
total_bytes_received = 0

# ------------------------------
# Define wrapper functions for sending commands.
# These functions use a socket timeout and a loop to read all available data.

def send_custom(command_str):
    """Send a plain-text command (custom protocol) to the server and return the response string."""
    global total_bytes_sent, total_bytes_received
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.settimeout(1.0)
            data = (command_str + "\n").encode("utf-8")
            total_bytes_sent += len(data)
            s.sendall(data)
            response_parts = []
            while True:
                try:
                    part = s.recv(4096)
                except socket.timeout:
                    break
                if not part:
                    break
                total_bytes_received += len(part)
                response_parts.append(part)
            response = b"".join(response_parts)
            return response.decode("utf-8").strip()
    except Exception as e:
        return f"ERROR: {e}"

def send_json(cmd_obj):
    """Send a JSON command to the server and return the parsed JSON response."""
    global total_bytes_sent, total_bytes_received
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.settimeout(1.0)
            msg = (json.dumps(cmd_obj) + "\n").encode("utf-8")
            total_bytes_sent += len(msg)
            s.sendall(msg)
            response_parts = []
            while True:
                try:
                    part = s.recv(4096)
                except socket.timeout:
                    break
                if not part:
                    break
                total_bytes_received += len(part)
                response_parts.append(part)
            response = b"".join(response_parts)
            return json.loads(response.decode("utf-8").strip())
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# Choose the appropriate send function based on protocol.
if protocol == "json":
    send_command = send_json
else:
    send_command = send_custom

# ------------------------------
# Helper functions for test commands

def create_account(user, hashed):
    if protocol == "json":
        cmd = {"command": "CREATE", "username": user, "hashed_password": hashed}
        return send_command(cmd)
    else:
        return send_command(f"CREATE {user} {hashed}")

def login_account(user, hashed):
    if protocol == "json":
        cmd = {"command": "LOGIN", "username": user, "hashed_password": hashed}
        return send_command(cmd)
    else:
        return send_command(f"LOGIN {user} {hashed}")

def logout_account(user, hashed):
    if protocol == "json":
        cmd = {"command": "LOGOUT", "username": user, "hashed_password": hashed}
        return send_command(cmd)
    else:
        return send_command(f"LOGOUT {user} {hashed}")

def delete_account(user, hashed):
    if protocol == "json":
        cmd = {"command": "DELETE", "username": user, "hashed_password": hashed}
        return send_command(cmd)
    else:
        return send_command(f"DELETE {user} {hashed}")

def send_message(sender, hashed, recipient, message):
    if protocol == "json":
        cmd = {"command": "SEND", "sender": sender, "hashed_password": hashed, "recipient": recipient, "message": message}
        return send_command(cmd)
    else:
        return send_command(f"SEND {sender} {hashed} {recipient} {message}")

def read_conversation(user, hashed, other, n):
    if protocol == "json":
        cmd = {"command": "READ_CONVO", "username": user, "hashed_password": hashed, "other_user": other, "n": n}
        return send_command(cmd)
    else:
        return send_command(f"READ_CONVO {user} {hashed} {other} {n}")

def read_full_conversation(user, hashed, other, n):
    if protocol == "json":
        cmd = {"command": "READ_FULL_CONVO", "username": user, "hashed_password": hashed, "other_user": other, "n": n}
        return send_command(cmd)
    else:
        return send_command(f"READ_FULL_CONVO {user} {hashed} {other} {n}")

# ------------------------------
# Efficiency Test

def run_efficiency_test():
    print("Running Efficiency Test...")
    start_time = time.time()
    global total_bytes_sent, total_bytes_received
    total_bytes_sent = 0
    total_bytes_received = 0

    # Create two accounts: TestUser1 and TestUser2.
    hashed = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # hash for "password"
    create_account("TestUser1", hashed)
    create_account("TestUser2", hashed)
    # TestUser1 sends 20 messages ("a") to TestUser2.
    for i in range(20):
        send_message("TestUser1", hashed, "TestUser2", "a")
    # TestUser2 reads all 20 messages.
    read_conversation("TestUser2", hashed, "TestUser1", 20)
    # Delete both accounts.
    delete_account("TestUser1", hashed)
    delete_account("TestUser2", hashed)
    end_time = time.time()
    elapsed = end_time - start_time
    print("Efficiency Test Results:")
    print(f"  Elapsed Time: {elapsed:.3f} seconds")
    print(f"  Total Bytes Sent: {total_bytes_sent} bytes")
    print(f"  Total Bytes Received: {total_bytes_received} bytes")
    print("")

# ------------------------------
# Scaling Test

def run_scaling_test():
    print("Running Scaling Test...")
    start_time = time.time()
    global total_bytes_sent, total_bytes_received
    total_bytes_sent = 0
    total_bytes_received = 0
    # Create 10 accounts: TestUser1, TestUser2, ... TestUser10.
    hashed = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    accounts = [f"TestUser{i}" for i in range(1, 11)]
    for user in accounts:
        create_account(user, hashed)
    # For each unique pair, have the lower-indexed account send "hello" to the higher-indexed account.
    latencies = []
    threads = []

    def send_hello(sender, recipient):
        t0 = time.time()
        send_message(sender, hashed, recipient, "hello")
        t1 = time.time()
        latencies.append(t1 - t0)

    # There are C(10,2) = 45 unique pairs.
    for i in range(len(accounts)):
        for j in range(i+1, len(accounts)):
            t = threading.Thread(target=send_hello, args=(accounts[i], accounts[j]))
            threads.append(t)
            t.start()
    for t in threads:
        t.join()
    # Delete all accounts.
    for user in accounts:
        delete_account(user, hashed)
    end_time = time.time()
    elapsed = end_time - start_time
    throughput = 45 / elapsed if elapsed > 0 else 0
    max_latency = max(latencies) if latencies else 0
    print("Scaling Test Results:")
    print(f"  Elapsed Time: {elapsed:.3f} seconds")
    print(f"  Throughput: {throughput:.3f} messages/second")
    print(f"  Maximum Message Latency: {max_latency:.3f} seconds")
    print(f"  Total Bytes Sent: {total_bytes_sent} bytes")
    print(f"  Total Bytes Received: {total_bytes_received} bytes")
    print("")

# ------------------------------
# Main Routine

if __name__ == "__main__":
    print(f"Running tests using {protocol.upper()} protocol on {HOST}:{PORT}")
    print("----------------------------------------------------")
    run_efficiency_test()
    run_scaling_test()
