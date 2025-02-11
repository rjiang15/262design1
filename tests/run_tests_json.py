#!/usr/bin/env python3
import subprocess
import time
import socket
import json
import re

# ANSI escape codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

HOST = "127.0.0.1"
PORT = 54400

def send_command_json(cmd):
    """Send a JSON command to the server and return the parsed JSON response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall((json.dumps(cmd) + "\n").encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            return json.loads(data.strip())
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

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
    passed = 0
    global_sql_id = None  # To hold the SQL injection message id

    import hashlib
    def hash_password(pw):
        return hashlib.sha256(pw.encode()).hexdigest()
    pw_hash = hash_password("password")
    wrong_hash = hash_password("hello")

    tests = [
        # ACCOUNT TESTS
        {
            "description": "Create TestUser1 account",
            "command": {"command": "CREATE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "Create TestUser1 account again (should fail)",
            "command": {"command": "CREATE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account already exists",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "already exists" in res.get("message", "")
        },
        {
            "description": "Log into TestUser2 (nonexistent)",
            "command": {"command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account does not exist",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "does not exist" in res.get("message", "")
        },
        {
            "description": "Create TestUser2 account",
            "command": {"command": "CREATE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "Log into TestUser2 with wrong password",
            "command": {"command": "LOGIN", "username": "TestUser2", "hashed_password": wrong_hash},
            "expected": "Incorrect password",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "Incorrect" in res.get("message", "")
        },
        {
            "description": "Log into TestUser1 properly",
            "command": {"command": "LOGIN", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").startswith("OK") and "Login successful" in res.get("message", "")
        },
        {
            "description": "Log into TestUser2 properly",
            "command": {"command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").startswith("OK") and "Login successful" in res.get("message", "")
        },
        {
            "description": "Log out of TestUser2",
            "command": {"command": "LOGOUT", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Logged out",
            "check": lambda res: res.get("status", "").startswith("OK") and "Logged out" in res.get("message", "")
        },
        # MESSAGE TESTS
        {
            "description": "TestUser1 sends TestUser2 '1'",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "1"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").startswith("OK") and "Message sent with id" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 an empty string (should fail)",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": ""},
            "expected": "Empty message not allowed.",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "Empty message not allowed" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 a SQL injection attack under 256 chars",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "a'); DROP TABLE accounts;--"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "TestUser1 deletes the SQL injection attack message",
            "command": {"command": "DELETE_MSG", "username": "TestUser1", "hashed_password": pw_hash, "target": "{SQLID}"},
            "expected": "Deleted message ids",
            "check": lambda res: res.get("status", "").startswith("OK") and "Deleted message ids" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 a string of length 257",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "a" * 257},
            "expected": "Message too long",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "too long" in res.get("message", "")
        },
        {
            "description": "TestUser1 sends TestUser2 '2'",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "2"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "TestUser1 sends TestUser2 '3'",
            "command": {"command": "SEND", "sender": "TestUser1", "hashed_password": pw_hash, "recipient": "TestUser2", "message": "3"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        # READING CHECKS
        {
            "description": "Log into TestUser2 properly",
            "command": {"command": "LOGIN", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Login successful",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "TestUser2 checks unread messages count (should be 3)",
            "command": {"command": "LIST_CONVERSATIONS", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Total unread messages: 3",
            "check": lambda res: "Total unread messages: 3" in res.get("message", "")
        },
        {
            "description": "TestUser2 opens conversation with TestUser1 to read 2 messages",
            "command": {"command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": 2},
            "expected": "should include messages with '1' and '2'",
            "check": lambda res: "1" in json.dumps(res) and "2" in json.dumps(res)
        },
        {
            "description": "TestUser2 checks unread messages count again (should be 1)",
            "command": {"command": "LIST_CONVERSATIONS", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Total unread messages: 1",
            "check": lambda res: "Total unread messages: 1" in res.get("message", "")
        },
        {
            "description": "TestUser2 selects view more (requesting 5 messages should fail)",
            "command": {"command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": 5},
            "expected": "The allowed maximum value is",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "allowed maximum" in res.get("message", "")
        },
        {
            "description": "TestUser2 asks to see 'a' messages (invalid number)",
            "command": {"command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": "a"},
            "expected": "n must be an integer",
            "check": lambda res: res.get("status", "").startswith("ERROR") and "n must be an integer" in res.get("message", "")
        },
        {
            "description": "TestUser2 selects to read 1 message (should read '3')",
            "command": {"command": "READ_CONVO", "username": "TestUser2", "hashed_password": pw_hash, "other_user": "TestUser1", "n": 1},
            "expected": "3",
            "check": lambda res: "3" in json.dumps(res)
        },
        # LIVE MESSAGE TESTS
        {
            "description": "TestUser2 sends a message to TestUser1 saying 'hello'",
            "command": {"command": "SEND", "sender": "TestUser2", "hashed_password": pw_hash, "recipient": "TestUser1", "message": "hello"},
            "expected": "Message sent with id",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "TestUser1 checks messages with TestUser2 (should get 'hello' instantly)",
            "command": {"command": "POLL_CONVO", "username": "TestUser1", "hashed_password": pw_hash, "other_user": "TestUser2"},
            "expected": "hello",
            "check": lambda res: "hello" in json.dumps(res)
        },
        # DELETION CHECKS
        {
            "description": "Delete TestUser2 account",
            "command": {"command": "DELETE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").startswith("OK") and "Account deleted" in res.get("message", "")
        },
        {
            "description": "TestUser1 checks conversations (should not list TestUser2)",
            "command": {"command": "LIST_CONVERSATIONS", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "TestUser2 should not appear",
            "check": lambda res: "TestUser2" not in json.dumps(res)
        },
        {
            "description": "Create TestUser2 account again",
            "command": {"command": "CREATE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account created",
            "check": lambda res: res.get("status", "").startswith("OK")
        },
        {
            "description": "Check chat history between TestUser1 and TestUser2 (should be empty)",
            "command": {"command": "READ_FULL_CONVO", "username": "TestUser1", "hashed_password": pw_hash, "other_user": "TestUser2", "n": 50},
            "expected": "No messages",
            "check": lambda res: "No messages" in res.get("message", "")
        },
        {
            "description": "Delete TestUser2 account",
            "command": {"command": "DELETE", "username": "TestUser2", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").startswith("OK") and "Account deleted" in res.get("message", "")
        },
        {
            "description": "Delete TestUser1 account",
            "command": {"command": "DELETE", "username": "TestUser1", "hashed_password": pw_hash},
            "expected": "Account deleted",
            "check": lambda res: res.get("status", "").startswith("OK") and "Account deleted" in res.get("message", "")
        }
    ]

    total_tests = len(tests)
    passed_tests = 0

    for test in tests:
        # If the test command contains the placeholder {SQLID}, replace it with the stored value.
        if "target" in test["command"] and test["command"]["target"] == "{SQLID}":
            if global_sql_id is None:
                print(f"{RED}Error: SQLID not set before test: {test['description']}{RESET}")
                continue
            test["command"]["target"] = str(global_sql_id)
        print(f"Running Test {test_num}: {test['description']}")
        print(f"  Command: {json.dumps(test['command'])}")
        print(f"  Expected: {test['expected']}")
        result = send_command_json(test["command"])
        # Capture the SQL injection message id if this test is the SQL injection test.
        if test["description"].startswith("TestUser1 sends TestUser2 a SQL injection attack"):
            m = re.search(r"with id (\d+)", result.get("message", ""))
            if m:
                global_sql_id = m.group(1)
        if test["check"](result):
            print(f"  {GREEN}PASS{RESET}\n")
            passed_tests += 1
        else:
            print(f"  {RED}FAIL{RESET}\n  Got: {result}\n")
        test_num += 1

    # Summary
    summary = f"{passed_tests}/{total_tests} tests passed."
    if passed_tests == total_tests:
        print(f"{GREEN}{summary}{RESET}")
    else:
        print(f"{RED}{summary}{RESET}")

if __name__ == "__main__":
    print("Starting server_json.py...")
    server_proc = subprocess.Popen(["python", "server_json.py", "--host", HOST, "--port", str(PORT)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)  # Give server time to start

    try:
        run_tests()
    finally:
        server_proc.terminate()
        server_proc.wait()
        print("Server terminated.")
