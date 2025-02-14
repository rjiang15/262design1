#!/usr/bin/env python3
import subprocess
import time
import socket
import re
import json
import hashlib

# ANSI escape codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

HOST = "127.0.0.1"
PORT = 54400

# Global counters for bytes sent and received (if you wish to track them here)
total_bytes_sent = 0
total_bytes_received = 0

def send_command_json(cmd_obj):
    """Send a JSON command (with a trailing newline) to the server and return the parsed JSON response."""
    global total_bytes_sent, total_bytes_received
    # Ensure protocol version is present
    if "version" not in cmd_obj:
        cmd_obj["version"] = "1.0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            data = (json.dumps(cmd_obj) + "\n").encode("utf-8")
            total_bytes_sent += len(data)
            s.sendall(data)
            response = s.recv(4096)
            total_bytes_received += len(response)
            return json.loads(response.decode("utf-8").strip())
    except Exception as e:
        return {"version": "1.0", "status": "ERROR", "message": str(e)}

def print_result(test_num, description, expected, result, success):
    print(f"Test {test_num}: {description}")
    print(f"  Expected: {expected}")
    print(f"  Got     : {result}")
    if success:
        print(f"  {GREEN}PASS{RESET}\n")
    else:
        print(f"  {RED}FAIL{RESET}\n")

def run_tests():
    test_num = 1
    passed_tests = 0
    global_sql_id = None  # to store message id from SQL injection test

    def hash_password(pw):
        return hashlib.sha256(pw.encode()).hexdigest()

    pw_hash = hash_password("password")
    wrong_hash = hash_password("hello")

    # Each test is defined as a dictionary with:
    # - description: textual description
    # - command: a dictionary to send via JSON (which includes version, command, etc.)
    # - expected: a string (or substring) expected to be found in the response's message or status.
    # - check: a function that receives the JSON response (a dict) and returns True if the test passes.
    tests = [
        # ACCOUNT TESTS
        {
            "description": "Create TestUser1 account",
            "command": {"version": "1.0", "command": "CREATE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").upper() == "OK" and "created" in res.get("message", "")
        },
        {
            "description": "Create TestUser1 account again (should fail)",
            "command": {"version": "1.0", "command": "CREATE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account already exists",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "already exists" in res.get("message", "")
        },
        {
            "description": "Log into TestUser2 (nonexistent)",
            "command": {"version": "1.0", "command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account does not exist",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "does not exist" in res.get("message", "")
        },
        {
            "description": "Create TestUser2 account",
            "command": {"version": "1.0", "command": "CREATE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").upper() == "OK"
        },
        {
            "description": "Log into TestUser2 with wrong password",
            "command": {"version": "1.0", "command": "LOGIN", "username": "TestUser2", "hashed_password": wrong_hash},
            "expected": "Incorrect password",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "Incorrect" in res.get("message", "")
        },
        {
            "description": "Log into TestUser1 properly",
            "command": {"version": "1.0", "command": "LOGIN", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Login successful" in res.get("message", "")
        },
        {
            "description": "Log into TestUser2 properly",
            "command": {"version": "1.0", "command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Login successful" in res.get("message", "")
        },
        {
            "description": "Log out of TestUser2",
            "command": {"version": "1.0", "command": "LOGOUT", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Logged out",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Logged out" in res.get("message", "")
        },
        # MESSAGE TESTS
        {
            "description": "TestUser1 sends TestUser2 '1'",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "1"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Message sent with id" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 an empty string (should fail)",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": ""},
            "expected": "Empty message not allowed",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "Empty message" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 a SQL injection attack under 256 chars",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "a'); DROP TABLE accounts;--"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Message sent with id" in res.get("message", "")
        },
        {
            "description": "TestUser1 deletes the SQL injection attack message",
            "command": {"version": "1.0", "command": "DELETE_MSG", "username": "TestUser1", "hashed_password": pw_hash, "target": "{SQLID}"},
            "expected": "Deleted message ids",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Deleted message ids" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 a string of length 257",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "a" * 257},
            "expected": "Message too long",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "Message too long" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 '2'",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "2"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").upper() == "OK"
        },
        {
            "description": "TestUser1 sends TestUser2 '3'",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "3"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").upper() == "OK"
        },
        # READING CHECKS
        {
            "description": "Log into TestUser2 properly",
            "command": {"version": "1.0", "command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Login successful" in res.get("message", "")
        },
        {
            "description": "TestUser2 checks unread messages count (should be 3)",
            "command": {"version": "1.0", "command": "LIST_CONVERSATIONS", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Total unread messages: 3",
            "check": lambda res: res.get("message", "").find("Total unread messages: 3") != -1
        },
        {
            "description": "TestUser2 opens conversation with TestUser1 to read 2 messages",
            "command": {"version": "1.0", "command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": "2"},
            "expected": "1",
            "check": lambda res: any("1" in msg.get("content", "") for msg in res.get("messages", [])) and any("2" in msg.get("content", "") for msg in res.get("messages", []))
        },
        {
            "description": "TestUser2 checks unread messages count again (should be 1)",
            "command": {"version": "1.0", "command": "LIST_CONVERSATIONS", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Total unread messages: 1",
            "check": lambda res: res.get("message", "").find("Total unread messages: 1") != -1
        },
        {
            "description": "TestUser2 selects view more (requesting 5 messages should fail)",
            "command": {"version": "1.0", "command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": "5"},
            "expected": "The allowed maximum value is",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "allowed maximum" in res.get("message", "")
        },
        {
            "description": "TestUser2 asks to see 'a' messages (invalid number)",
            "command": {"version": "1.0", "command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": "a"},
            "expected": "n must be an integer",
            "check": lambda res: res.get("status", "").upper() == "ERROR" and "n must be an integer" in res.get("message", "")
        },
        {
            "description": "TestUser2 selects to read 1 message (should read '3')",
            "command": {"version": "1.0", "command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": 1},
            "expected": "3",
            "check": lambda res: any("3" in msg.get("content", "") for msg in res.get("messages", []))
        },
        # LIVE MESSAGE TESTS
        {
            "description": "TestUser2 sends a message to TestUser1 saying 'hello'",
            "command": {"version": "1.0", "command": "SEND", "sender": "TestUser2", "hashed_password": pw_hash, "recipient": "TestUser1", "message": "hello"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Message sent with id" in res.get("message", "")
        },
        {
            "description": "TestUser1 checks messages with TestUser2 (should get 'hello' instantly)",
            "command": {"version": "1.0", "command": "POLL_CONVO", "username": "TestUser1", "hashed_password": pw_hash, "other_user": "TestUser2"},
            "expected": "hello",
            "check": lambda res: any("hello" in msg.get("content", "") for msg in res.get("messages", []))
        },
        # DELETION CHECKS
        {
            "description": "Delete TestUser2 account",
            "command": {"version": "1.0", "command": "DELETE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Account deleted" in res.get("message", "")
        },
        {
            "description": "TestUser1 checks conversations (should not list TestUser2)",
            "command": {"version": "1.0", "command": "LIST_CONVERSATIONS", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "TestUser2 should not appear",
            "check": lambda res: "TestUser2" not in json.dumps(res)
        },
        {
            "description": "Create TestUser2 account again",
            "command": {"version": "1.0", "command": "CREATE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").upper() == "OK"
        },
        {
            "description": "Check chat history between TestUser1 and TestUser2 (should be empty)",
            "command": {"version": "1.0", "command": "READ_FULL_CONVO", "username": "TestUser1", "hashed_password": pw_hash, "other_user": "TestUser2", "n": 50},
            "expected": "No messages",
            "check": lambda res: "No messages" in res.get("message", "")
        },
        {
            "description": "Delete TestUser2 account",
            "command": {"version": "1.0", "command": "DELETE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Account deleted" in res.get("message", "")
        },
        {
            "description": "Delete TestUser1 account",
            "command": {"version": "1.0", "command": "DELETE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").upper() == "OK" and "Account deleted" in res.get("message", "")
        }
    ]

    for test in tests:
        # If the test command contains the placeholder {SQLID}, replace it with the stored value.
        if "target" in test["command"] and isinstance(test["command"]["target"], str) and "{SQLID}" in test["command"]["target"]:
            if global_sql_id is None:
                print(f"{RED}Error: SQLID not set before test: {test['description']}{RESET}")
                continue
            test["command"]["target"] = test["command"]["target"].replace("{SQLID}", str(global_sql_id))
        print(f"Running Test {test_num}: {test['description']}")
        print(f"  Command: {json.dumps(test['command'])}")
        print(f"  Expected: {test['expected']}")
        result = send_command_json(test["command"])
        # Capture the SQL injection message id if this test is the SQL injection test.
        if "SQL injection attack" in test["description"]:
            m = re.search(r"with id (\d+)", result.get("message", ""))
            if m:
                global_sql_id = m.group(1)
        if test["check"](result):
            print(f"  {GREEN}PASS{RESET}\n")
            passed_tests += 1
        else:
            print(f"  {RED}FAIL{RESET}\n  Got: {json.dumps(result)}\n")
        test_num += 1

    # Summary of results
    total_tests = len(tests)
    summary = f"{passed_tests}/{total_tests} tests passed."
    if passed_tests == total_tests:
        print(f"{GREEN}{summary}{RESET}")
    else:
        print(f"{RED}{summary}{RESET}")
    print(f"Total bytes sent (client side): {total_bytes_sent} bytes")
    print(f"Total bytes received (client side): {total_bytes_received} bytes")

if __name__ == "__main__":
    print("Make sure the JSON server (server_json.py) is running before starting the tests.")
    time.sleep(1)  # Brief pause to ensure server readiness
    run_tests()
