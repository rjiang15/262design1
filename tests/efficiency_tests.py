#!/usr/bin/env python3
import argparse
import socket
import json
import time

# For gRPC, if/when used
import grpc

# If you have the same stats_interceptor from your scaling tests:
from my_grpc.stats_interceptor import ByteCountingInterceptor
from my_grpc import chat_pb2, chat_pb2_grpc

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="Run efficiency tests for custom, JSON, or gRPC.")
parser.add_argument("--protocol", type=str, choices=["json", "custom", "grpc"], default="custom",
                    help="Protocol to test: 'json', 'custom', or 'grpc' (default: custom)")

parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
parser.add_argument("--port", type=int, default=54400, help="Server port (default: 54400)")
args = parser.parse_args()

HOST = args.host
PORT = args.port
protocol = args.protocol

# --------------------------------------------------------------
# For CUSTOM/JSON protocols, track socket-level bytes globally:
# --------------------------------------------------------------
total_bytes_sent = 0
total_bytes_received = 0
PROTOCOL_VERSION = "1.0"

def send_custom(command_str):
    """Send a plain-text command (custom protocol) with a version prefix to the server."""
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

# We'll define a separate "send_command" for custom vs JSON vs gRPC
# but for custom/JSON we just reuse the above logic:
def create_account_custom_or_json(user, hashed):
    if protocol == "json":
        cmd = {"command": "CREATE", "username": user, "hashed_password": hashed}
        return send_json(cmd)
    else:
        return send_custom(f"CREATE {user} {hashed}")

def login_account_custom_or_json(user, hashed):
    if protocol == "json":
        cmd = {"command": "LOGIN", "username": user, "hashed_password": hashed}
        return send_json(cmd)
    else:
        return send_custom(f"LOGIN {user} {hashed}")

def delete_account_custom_or_json(user, hashed):
    if protocol == "json":
        cmd = {"command": "DELETE", "username": user, "hashed_password": hashed}
        return send_json(cmd)
    else:
        return send_custom(f"DELETE {user} {hashed}")

def send_message_custom_or_json(sender, hashed, recipient, message):
    if protocol == "json":
        cmd = {
            "command": "SEND",
            "sender": sender,
            "hashed_password": hashed,
            "recipient": recipient,
            "message": message
        }
        return send_json(cmd)
    else:
        return send_custom(f"SEND {sender} {hashed} {recipient} {message}")

def read_conversation_custom_or_json(user, hashed, other, n):
    if protocol == "json":
        cmd = {
            "command": "READ_CONVO",
            "username": user,
            "hashed_password": hashed,
            "other_user": other,
            "n": n
        }
        return send_json(cmd)
    else:
        return send_custom(f"READ_CONVO {user} {hashed} {other} {n}")

# --------------------------------------------
# gRPC equivalents of these same operations
# --------------------------------------------
channel = None
stub = None

def create_account_grpc(user, hashed):
    req = chat_pb2.AccountRequest(username=user, hashed_password=hashed)
    resp = stub.CreateAccount(req)
    return resp.status  # e.g. "OK" or "ERROR"

def login_account_grpc(user, hashed):
    req = chat_pb2.AccountRequest(username=user, hashed_password=hashed)
    resp = stub.Login(req)
    return resp.status

def delete_account_grpc(user, hashed):
    req = chat_pb2.AccountRequest(username=user, hashed_password=hashed)
    resp = stub.DeleteAccount(req)
    return resp.status

def send_message_grpc(sender, hashed, recipient, message):
    req = chat_pb2.SendMessageRequest(
        sender=sender,
        hashed_password=hashed,
        recipient=recipient,
        message=message
    )
    resp = stub.SendMessage(req)
    return resp.status

def read_conversation_grpc(user, hashed, other, n):
    # The server's gRPC method name is probably ReadConvo or something similar.
    # We'll assume it's named ReadConvo and takes a ReadConvoRequest.
    req = chat_pb2.ReadConvoRequest(
        username=user,
        hashed_password=hashed,
        other_user=other,
        n=str(n)
    )
    resp = stub.ReadConvo(req)
    return resp.status  # e.g. "OK" or "ERROR"

# Decide which set of functions to use, based on 'protocol'
if protocol == "grpc":
    # 1) Build a base channel
    base_channel = grpc.insecure_channel(f"{HOST}:{PORT}")
    # 2) (Optional) attach ByteCountingInterceptor if you want to measure raw protobuf bytes
    intercept_channel = grpc.intercept_channel(base_channel, ByteCountingInterceptor())
    # 3) Create stub
    stub = chat_pb2_grpc.ChatServiceStub(intercept_channel)

    create_account = create_account_grpc
    login_account = login_account_grpc
    delete_account = delete_account_grpc
    send_message = send_message_grpc
    read_conversation = read_conversation_grpc
else:
    # custom or json
    create_account = create_account_custom_or_json
    login_account = login_account_custom_or_json
    delete_account = delete_account_custom_or_json
    send_message = send_message_custom_or_json
    read_conversation = read_conversation_custom_or_json

# ------------------------------
# Efficiency Test
# ------------------------------
def run_efficiency_test():
    print("Running Efficiency Test...")

    # For custom/JSON, reset these to measure socket-level bytes.
    global total_bytes_sent, total_bytes_received
    total_bytes_sent = 0
    total_bytes_received = 0

    # For gRPC, if you want to measure protobuf bytes:
    if protocol == "grpc":
        ByteCountingInterceptor.reset_counters()

    start_time = time.time()

    hashed = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # hash for "password"

    # Create two accounts
    create_account("TestUser1", hashed)
    create_account("TestUser2", hashed)

    # TestUser1 sends 20 messages to TestUser2
    for i in range(20):
        send_message("TestUser1", hashed, "TestUser2", "a")

    # TestUser2 reads all 20
    read_conversation("TestUser2", hashed, "TestUser1", 20)

    # Delete both
    delete_account("TestUser1", hashed)
    delete_account("TestUser2", hashed)

    end_time = time.time()
    elapsed = end_time - start_time

    # For gRPC, retrieve final protobuf byte counts from the interceptor
    if protocol == "grpc":
        sent, received = ByteCountingInterceptor.get_counters()
    else:
        sent, received = total_bytes_sent, total_bytes_received

    print("Efficiency Test Results:")
    print(f"  Elapsed Time: {elapsed:.3f} seconds")
    print(f"  Total Bytes Sent: {sent} bytes")
    print(f"  Total Bytes Received: {received} bytes")

if __name__ == "__main__":
    print(f"Running efficiency tests using {protocol.upper()} protocol on {HOST}:{PORT}")
    run_efficiency_test()
