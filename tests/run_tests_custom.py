#!/usr/bin/env python3
import subprocess
import time
import socket
import re

# ANSI escape codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

HOST = "127.0.0.1"
PORT = 54400

def send_command(command):
    """Send a command string (terminated by newline) to the server and return its response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall((command + "\n").encode("utf-8"))
            data = s.recv(4096).decode("utf-8")
            return data.strip()
    except Exception as e:
        return f"ERROR: {e}"

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
    global_sql_id = None  # Will hold the message id of the SQL injection attack message

    import hashlib
    def hash_password(pw):
        return hashlib.sha256(pw.encode()).hexdigest()
    pw_hash = hash_password("password")
    wrong_hash = hash_password("hello")

    tests = [
        # ACCOUNT TESTS
        {
            "description": "Create TestUser1 account",
            "command": f"CREATE TestUser1 {pw_hash}",
            "expected": "OK: Account created",
            "check": lambda res: res.startswith("OK:")
        },
        {
            "description": "Create TestUser1 account again (should fail)",
            "command": f"CREATE TestUser1 {pw_hash}",
            "expected": "ERROR: Account already exists",
            "check": lambda res: "ERROR" in res and "already exists" in res
        },
        {
            "description": "Log into TestUser2 (nonexistent)",
            "command": f"LOGIN TestUser2 {pw_hash}",
            "expected": "ERROR: Account does not exist",
            "check": lambda res: "ERROR" in res and "does not exist" in res
        },
        {
            "description": "Create TestUser2 account",
            "command": f"CREATE TestUser2 {pw_hash}",
            "expected": "OK: Account created",
            "check": lambda res: res.startswith("OK:")
        },
        {
            "description": "Log into TestUser2 with wrong password",
            "command": f"LOGIN TestUser2 {wrong_hash}",
            "expected": "ERROR: Incorrect password",
            "check": lambda res: "ERROR" in res and "Incorrect" in res
        },
        {
            "description": "Log into TestUser1 properly",
            "command": f"LOGIN TestUser1 {pw_hash}",
            "expected": "OK: Login successful",
            "check": lambda res: "OK: Login successful" in res
        },
        {
            "description": "Log into TestUser2 properly",
            "command": f"LOGIN TestUser2 {pw_hash}",
            "expected": "OK: Login successful",
            "check": lambda res: "OK: Login successful" in res
        },
        {
            "description": "Log out of TestUser2",
            "command": f"LOGOUT TestUser2 {pw_hash}",
            "expected": "OK: Logged out",
            "check": lambda res: "OK: Logged out" in res
        },
        # MESSAGE TESTS
        {
            "description": "TestUser1 sends TestUser2 '1'",
            "command": f"SEND TestUser1 {pw_hash} TestUser2 1",
            "expected": "OK: Message sent with id",
            "check": lambda res: "OK: Message sent" in res
        },
        {
            "description": "TestUser1 sends TestUser2 an empty string (should fail)",
            "command": f"SEND TestUser1 {pw_hash} TestUser2 ",
            "expected": "ERROR: Usage: SEND sender hashed_password recipient message",
            "check": lambda res: "ERROR: Usage: SEND" in res
        },
        {
            "description": "TestUser1 sends TestUser2 a SQL injection attack under 256 chars",
            "command": f'SEND TestUser1 {pw_hash} TestUser2 "a\'); DROP TABLE accounts;--"',
            "expected": "OK: Message sent with id",
            "check": lambda res: "OK: Message sent" in res
        },
        {
            "description": "TestUser1 deletes the SQL injection attack message",
            "command": f"DELETE_MSG TestUser1 {pw_hash} {{SQLID}}",
            "expected": "OK: Deleted message ids",
            "check": lambda res: "OK: Deleted message ids" in res
        },
        {
            "description": "TestUser1 sends TestUser2 a string of length 257",
            "command": f"SEND TestUser1 {pw_hash} TestUser2 " + "a" * 257,
            "expected": "ERROR: Message too long",
            "check": lambda res: "ERROR" in res and "too long" in res
        },
        {
            "description": "TestUser1 sends TestUser2 '2'",
            "command": f"SEND TestUser1 {pw_hash} TestUser2 2",
            "expected": "OK: Message sent with id",
            "check": lambda res: "OK: Message sent" in res
        },
        {
            "description": "TestUser1 sends TestUser2 '3'",
            "command": f"SEND TestUser1 {pw_hash} TestUser2 3",
            "expected": "OK: Message sent with id",
            "check": lambda res: "OK: Message sent" in res
        },
        # READING CHECKS
        {
            "description": "Log into TestUser2 properly",
            "command": f"LOGIN TestUser2 {pw_hash}",
            "expected": "OK: Login successful",
            "check": lambda res: "OK: Login successful" in res
        },
        {
            "description": "TestUser2 checks unread messages count (should be 3)",
            "command": f"LIST_CONVERSATIONS TestUser2 {pw_hash}",
            "expected": "Unread: 3",
            "check": lambda res: "Unread: 3" in res
        },
        {
            "description": "TestUser2 opens conversation with TestUser1 to read 2 messages",
            "command": f"READ_CONVO TestUser2 {pw_hash} TestUser1 2",
            "expected": "1 and 2",
            "check": lambda res: "1" in res and "2" in res
        },
        {
            "description": "TestUser2 checks unread messages count again (should be 1)",
            "command": f"LIST_CONVERSATIONS TestUser2 {pw_hash}",
            "expected": "Unread: 1",
            "check": lambda res: "Unread: 1" in res
        },
        {
            "description": "TestUser2 selects view more (requesting 5 messages should fail)",
            "command": f"READ_CONVO TestUser2 {pw_hash} TestUser1 5",
            "expected": "ERROR",
            "check": lambda res: "ERROR" in res
        },
        {
            "description": "TestUser2 asks to see 'a' messages (invalid number)",
            "command": f"READ_CONVO TestUser2 {pw_hash} TestUser1 a",
            "expected": "ERROR",
            "check": lambda res: "ERROR" in res
        },
        {
            "description": "TestUser2 selects to read 1 message (should read '3')",
            "command": f"READ_CONVO TestUser2 {pw_hash} TestUser1 1",
            "expected": "3",
            "check": lambda res: "3" in res
        },
        # LIVE MESSAGE TESTS
        {
            "description": "TestUser2 sends a message to TestUser1 saying 'hello'",
            "command": f"SEND TestUser2 {pw_hash} TestUser1 hello",
            "expected": "OK: Message sent with id",
            "check": lambda res: "OK: Message sent" in res
        },
        {
            "description": "TestUser1 checks messages with TestUser2 (should get 'hello' instantly)",
            "command": f"POLL_CONVO TestUser1 {pw_hash} TestUser2",
            "expected": "hello",
            "check": lambda res: "hello" in res
        },
        # DELETION CHECKS
        {
            "description": "Delete TestUser2 account",
            "command": f"DELETE TestUser2 {pw_hash}",
            "expected": "OK: Account deleted",
            "check": lambda res: "OK: Account deleted" in res
        },
        {
            "description": "TestUser1 checks conversations (should not list TestUser2)",
            "command": f"LIST_CONVERSATIONS TestUser1 {pw_hash}",
            "expected": "TestUser2 should not appear",
            "check": lambda res: "TestUser2" not in res
        },
        {
            "description": "Create TestUser2 account again",
            "command": f"CREATE TestUser2 {pw_hash}",
            "expected": "OK: Account created",
            "check": lambda res: res.startswith("OK:")
        },
        {
            "description": "Check chat history between TestUser1 and TestUser2 (should be empty)",
            "command": f"READ_FULL_CONVO TestUser1 {pw_hash} TestUser2 50",
            "expected": "No messages",
            "check": lambda res: "No messages" in res
        },
        {
            "description": "Delete TestUser2 account",
            "command": f"DELETE TestUser2 {pw_hash}",
            "expected": "OK: Account deleted",
            "check": lambda res: "OK: Account deleted" in res
        },
        {
            "description": "Delete TestUser1 account",
            "command": f"DELETE TestUser1 {pw_hash}",
            "expected": "OK: Account deleted",
            "check": lambda res: "OK: Account deleted" in res
        }
    ]

    for test in tests:
        # If the test command contains the placeholder {SQLID}, replace it with the stored value.
        if "{SQLID}" in test["command"]:
            if global_sql_id is None:
                print(f"{RED}Error: SQLID not set before test: {test['description']}{RESET}")
                continue
            test["command"] = test["command"].replace("{SQLID}", str(global_sql_id))
        print(f"Running Test {test_num}: {test['description']}")
        print(f"  Command: {test['command']}")
        print(f"  Expected: {test['expected']}")
        result = send_command(test["command"])
        # Capture the SQL injection message id if this test is the SQL injection test.
        if "SQL injection attack" in test["description"]:
            m = re.search(r"with id (\d+)", result)
            if m:
                global_sql_id = m.group(1)
        if test["check"](result):
            print(f"  {GREEN}PASS{RESET}\n")
            passed_tests += 1
        else:
            print(f"  {RED}FAIL{RESET}\n  Got: {result}\n")
        test_num += 1

    # Summary of results
    total_tests = len(tests)
    summary = f"{passed_tests}/{total_tests} tests passed."
    if passed_tests == total_tests:
        print(f"{GREEN}{summary}{RESET}")
    else:
        print(f"{RED}{summary}{RESET}")

if __name__ == "__main__":
    print("Starting server.py...")
    server_proc = subprocess.Popen(["python", "server.py", "--host", HOST, "--port", str(PORT)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)  # Give server time to start

    try:
        run_tests()
    finally:
        server_proc.terminate()
        server_proc.wait()
        print("Server terminated.")
