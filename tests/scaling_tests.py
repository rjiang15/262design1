#!/usr/bin/env python3
import argparse
import socket
import json
import time
import threading

import grpc

# Generated code + interceptor
from my_grpc import chat_pb2, chat_pb2_grpc
from my_grpc.stats_interceptor import ByteCountingInterceptor

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Run scaling tests for custom, JSON, or gRPC protocols.")
parser.add_argument("--protocol", type=str, choices=["json", "custom", "grpc"], default="custom",
                    help="Protocol to test: 'json', 'custom', or 'grpc' (default: custom)")
parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port (default: 54400)")
args = parser.parse_args()

HOST = args.host
PORT = args.port
protocol = args.protocol

# If we're using custom/JSON, we track socket-level bytes:
total_bytes_sent = 0
total_bytes_received = 0
PROTOCOL_VERSION = "1.0"

# We'll define create_account(), send_message(), and delete_account() for each protocol
channel = None
stub = None

# -----------------------
# CUSTOM PROTOCOL HELPERS
# -----------------------
def send_custom(command_str):
    global total_bytes_sent, total_bytes_received
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.settimeout(1.0)
            full_command = f"{PROTOCOL_VERSION} {command_str}"
            data = (full_command + "\n").encode("utf-8")
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

# ----------------------
# JSON PROTOCOL HELPERS
# ----------------------
def send_json(cmd_obj):
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

# -----------------------
# gRPC PROTOCOL HELPERS
# -----------------------
def create_account_grpc(username, hashed):
    req = chat_pb2.AccountRequest(username=username, hashed_password=hashed)
    resp = stub.CreateAccount(req)  # Interceptor will measure request/response.
    if resp.status == "OK":
        return "OK"
    return f"ERROR: {resp.message}"

def send_message_grpc(sender, hashed, recipient, message):
    req = chat_pb2.SendMessageRequest(
        sender=sender,
        hashed_password=hashed,
        recipient=recipient,
        message=message
    )
    resp = stub.SendMessage(req)
    if resp.status == "OK":
        return "OK"
    return f"ERROR: {resp.message}"

def delete_account_grpc(username, hashed):
    req = chat_pb2.AccountRequest(username=username, hashed_password=hashed)
    resp = stub.DeleteAccount(req)
    if resp.status == "OK":
        return "OK"
    return f"ERROR: {resp.message}"

# -----------------------------------------------------
# Decide how we do create/send/delete, per protocol
# -----------------------------------------------------
if protocol == "grpc":
    # Build a normal channel
    base_channel = grpc.insecure_channel(f"{HOST}:{PORT}")
    # Intercept it
    intercept_channel = grpc.intercept_channel(base_channel, ByteCountingInterceptor())
    # Create stub from the intercepted channel
    stub = chat_pb2_grpc.ChatServiceStub(intercept_channel)

    def create_account(user, hashed):
        return create_account_grpc(user, hashed)

    def send_message(sender, hashed, recipient, message):
        return send_message_grpc(sender, hashed, recipient, message)

    def delete_account(user, hashed):
        return delete_account_grpc(user, hashed)

elif protocol == "json":
    def create_account(user, hashed):
        cmd = {"command": "CREATE", "username": user, "hashed_password": hashed}
        return send_json(cmd)

    def send_message(sender, hashed, recipient, message):
        cmd = {
            "command": "SEND",
            "sender": sender,
            "hashed_password": hashed,
            "recipient": recipient,
            "message": message
        }
        return send_json(cmd)

    def delete_account(user, hashed):
        cmd = {"command": "DELETE", "username": user, "hashed_password": hashed}
        return send_json(cmd)

else:
    # protocol == "custom"
    def create_account(user, hashed):
        return send_custom(f"CREATE {user} {hashed}")

    def send_message(sender, hashed, recipient, message):
        return send_custom(f"SEND {sender} {hashed} {recipient} {message}")

    def delete_account(user, hashed):
        return send_custom(f"DELETE {user} {hashed}")

# ------------------------------
# SCALING TEST
# ------------------------------
def run_scaling_test(k):
    print(f"Running Scaling Test with k={k} accounts, protocol={protocol} ...")
    start_time = time.time()

    # If using custom/JSON, reset those global counters:
    global total_bytes_sent, total_bytes_received
    total_bytes_sent = 0
    total_bytes_received = 0

    # If using gRPC, reset the interceptor counters
    if protocol == "grpc":
        ByteCountingInterceptor.reset_counters()

    hashed = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # sha256("password")
    accounts = [f"TestUser{i}" for i in range(1, k + 1)]

    # 1) create k accounts
    for user in accounts:
        create_account(user, hashed)

    # 2) send "hello" for each unique pair
    latencies = []
    threads = []

    def send_hello(sender, recipient):
        t0 = time.time()
        send_message(sender, hashed, recipient, "hello")
        t1 = time.time()
        latencies.append(t1 - t0)

    for i in range(len(accounts)):
        for j in range(i+1, len(accounts)):
            t = threading.Thread(target=send_hello, args=(accounts[i], accounts[j]))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

    # 3) delete all
    for user in accounts:
        delete_account(user, hashed)

    end_time = time.time()
    elapsed = end_time - start_time
    num_messages = len(accounts) * (len(accounts) - 1) // 2
    throughput = num_messages / elapsed if elapsed > 0 else 0
    max_latency = max(latencies) if latencies else 0

    # If gRPC, read from the interceptor's counters
    if protocol == "grpc":
        sent, received = ByteCountingInterceptor.get_counters()
    else:
        sent, received = total_bytes_sent, total_bytes_received

    print("Scaling Test Results:")
    print(f"  Elapsed Time: {elapsed:.3f} seconds")
    print(f"  Throughput: {throughput:.3f} messages/second (for {num_messages} total messages)")
    print(f"  Maximum Message Latency: {max_latency:.3f} seconds")
    print(f"  Total Bytes Sent: {sent} bytes")
    print(f"  Total Bytes Received: {received} bytes")
    print()

if __name__ == "__main__":
    print(f"Running scaling tests using {protocol.upper()} protocol on {HOST}:{PORT}\n")
    for k in [10, 20, 30, 40]:
        run_scaling_test(k)
