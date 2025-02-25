#!/usr/bin/env python3
import subprocess
import time
import re
import hashlib

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grpc

# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'grpc'))

# import my_grpc.chat_pb2
# import my_grpc.chat_pb2_grpc

from my_grpc import chat_pb2, chat_pb2_grpc



# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

HOST = "127.0.0.1"
PORT = 50051
SERVER_CMD = ["python", "server_grpc.py", "--host", HOST, "--port", str(PORT)]

def hash_password(pw):
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()

def print_result(test_num, description, expected, actual, success):
    print(f"Test {test_num}: {description}")
    print(f"  Expected: {expected}")
    print(f"  Got     : {actual}")
    if success:
        print(f"  {GREEN}PASS{RESET}\n")
    else:
        print(f"  {RED}FAIL{RESET}\n")

class GRPCTestClient:
    """Mimics your custom-protocol approach but calls gRPC methods directly."""
    def __init__(self, host, port):
        self.channel = grpc.insecure_channel(f"{host}:{port}")
        self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)

    def create_account(self, username, hashed_pw):
        resp = self.stub.CreateAccount(chat_pb2.AccountRequest(
            username=username, hashed_password=hashed_pw
        ))
        return f"{resp.status}: {resp.message}"

    def login(self, username, hashed_pw):
        resp = self.stub.Login(chat_pb2.AccountRequest(
            username=username, hashed_password=hashed_pw
        ))
        return f"{resp.status}: {resp.message}"

    def logout(self, username, hashed_pw):
        resp = self.stub.Logout(chat_pb2.AccountRequest(
            username=username, hashed_password=hashed_pw
        ))
        return f"{resp.status}: {resp.message}"

    def delete_account(self, username, hashed_pw):
        resp = self.stub.DeleteAccount(chat_pb2.AccountRequest(
            username=username, hashed_password=hashed_pw
        ))
        return f"{resp.status}: {resp.message}"

    def send_message(self, sender, hashed_pw, recipient, message):
        req = chat_pb2.SendMessageRequest(
            sender=sender, hashed_password=hashed_pw,
            recipient=recipient, message=message
        )
        resp = self.stub.SendMessage(req)
        return f"{resp.status}: {resp.message}"

    def read_convo(self, username, hashed_pw, other_user, n_str):
        req = chat_pb2.ReadConvoRequest(
            username=username, hashed_password=hashed_pw,
            other_user=other_user, n=n_str
        )
        resp = self.stub.ReadConvo(req)
        return f"{resp.status}: {resp.message}" if resp.status.startswith("ERROR") else self._messages_to_string(resp)

    def read_full_convo(self, username, hashed_pw, other_user, n_str):
        req = chat_pb2.ReadConvoRequest(
            username=username, hashed_password=hashed_pw,
            other_user=other_user, n=n_str
        )
        resp = self.stub.ReadFullConvo(req)
        return f"{resp.status}: {resp.message}" if resp.status.startswith("ERROR") else self._messages_to_string(resp)

    def list_conversations(self, username, hashed_pw):
        req = chat_pb2.ListConversationsRequest(username=username, hashed_password=hashed_pw)
        resp = self.stub.ListConversations(req)
        if resp.total_unread or resp.conversations:
            lines = [f"Total unread: {resp.total_unread}"]
            for c in resp.conversations:
                lines.append(f"Partner: {c.partner}, Unread: {c.unread}, Last: {c.last_message}")
            return "\n".join(lines)
        else:
            return ""

    def poll_convo(self, username, hashed_pw, other_user):
        req = chat_pb2.PollConvoRequest(
            username=username, hashed_password=hashed_pw,
            other_user=other_user
        )
        resp = self.stub.PollConvo(req)
        if resp.status.startswith("ERROR"):
            return f"{resp.status}: {resp.message}"
        if resp.status.startswith("OK") and resp.message.startswith("No new messages"):
            return f"OK: No new messages"
        # Otherwise build lines
        lines = []
        for m in resp.messages:
            lines.append(f"{m.id}|||{m.sender}|||{m.content}")
        return "\n".join(lines)

    def delete_message(self, username, hashed_pw, msg_ids):
        req = chat_pb2.DeleteMessageRequest(
            username=username, hashed_password=hashed_pw,
            message_ids=msg_ids
        )
        resp = self.stub.DeleteMessage(req)
        return f"{resp.status}: {resp.message}"

    def _messages_to_string(self, read_resp):
        """Convert a ReadConvoResponse (or ReadFullConvoResponse) into the same style string for checks."""
        if not read_resp.messages:
            return f"{read_resp.status}: {read_resp.message}"
        lines = []
        for m in read_resp.messages:
            lines.append(f"{m.id}|||{m.sender}|||{m.content}")
        return "\n".join(lines)


def run_tests():
    client = GRPCTestClient(HOST, PORT)
    test_num = 1
    passed_tests = 0

    pw_hash = hash_password("password")
    wrong_hash = hash_password("hello")
    global_sql_id = None

    tests = [
        # ACCOUNT TESTS
        {
            "description": "Create TestUser1 account",
            "function": client.create_account,
            "args": ("TestUser1", pw_hash),
            "expected": "OK: Account created",
            "check": lambda r: ("OK:" in r and "created" in r)
        },
        {
            "description": "Create TestUser1 again (should fail)",
            "function": client.create_account,
            "args": ("TestUser1", pw_hash),
            "expected": "ERROR: Account already exists",
            "check": lambda r: ("ERROR" in r and "already exists" in r)
        },
        {
            "description": "Log into TestUser2 (nonexistent)",
            "function": client.login,
            "args": ("TestUser2", pw_hash),
            "expected": "ERROR: Account does not exist",
            "check": lambda r: ("ERROR" in r and "does not exist" in r)
        },
        {
            "description": "Create TestUser2 account",
            "function": client.create_account,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Account created",
            "check": lambda r: ("OK:" in r and "created" in r)
        },
        {
            "description": "Log into TestUser2 with wrong password",
            "function": client.login,
            "args": ("TestUser2", wrong_hash),
            "expected": "ERROR: Incorrect password",
            "check": lambda r: ("ERROR" in r and "Incorrect password" in r)
        },
        {
            "description": "Log into TestUser1 properly",
            "function": client.login,
            "args": ("TestUser1", pw_hash),
            "expected": "OK: Login successful",
            "check": lambda r: ("OK: Login successful" in r)
        },
        {
            "description": "Log into TestUser2 properly",
            "function": client.login,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Login successful",
            "check": lambda r: ("OK: Login successful" in r)
        },
        {
            "description": "Log out of TestUser2",
            "function": client.logout,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Logged out",
            "check": lambda r: ("OK: Logged out" in r)
        },
        # MESSAGE TESTS
        {
            "description": "TestUser1 sends TestUser2 '1'",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", "1"),
            "expected": "OK: Message sent with id",
            "check": lambda r: "OK: Message sent" in r
        },
        {
            "description": "TestUser1 sends TestUser2 an empty string (should fail)",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", ""),
            "expected": "ERROR: Usage: SEND",
            "check": lambda r: ("ERROR" in r and "Usage: SEND" in r)
        },
        {
            "description": "TestUser1 sends TestUser2 a SQL injection attack under 256 chars",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", "a'); DROP TABLE accounts;--"),
            "expected": "OK: Message sent with id",
            "check": lambda r: "OK: Message sent" in r
        },
        {
            "description": "Capture ID of the SQL injection message (next test deletes it)",
            "function": None,  # We'll handle capturing the ID after the previous test
        },
        {
            "description": "TestUser1 sends TestUser2 a string of length 257",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", "a"*257),
            "expected": "ERROR: Message too long",
            "check": lambda r: ("ERROR" in r and "too long" in r)
        },
        {
            "description": "TestUser1 sends TestUser2 '2'",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", "2"),
            "expected": "OK: Message sent with id",
            "check": lambda r: "OK: Message sent" in r
        },
        {
            "description": "TestUser1 sends TestUser2 '3'",
            "function": client.send_message,
            "args": ("TestUser1", pw_hash, "TestUser2", "3"),
            "expected": "OK: Message sent with id",
            "check": lambda r: "OK: Message sent" in r
        },
        # READING CHECKS
        {
            "description": "Log into TestUser2 properly",
            "function": client.login,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Login successful",
            "check": lambda r: ("OK: Login successful" in r)
        },
        {
            "description": "TestUser2 checks unread messages (should be 3)",
            "function": client.list_conversations,
            "args": ("TestUser2", pw_hash),
            "expected": "Unread: 3",
            "check": lambda r: ("Unread: 3" in r)
        },
        {
            "description": "TestUser2 opens conversation with TestUser1 to read 2 messages (should see '1' and '2')",
            "function": client.read_convo,
            "args": ("TestUser2", pw_hash, "TestUser1", "2"),
            "expected": "1 and 2",
            "check": lambda r: ("1" in r and "2" in r)
        },
        {
            "description": "TestUser2 checks unread messages again (should be 1)",
            "function": client.list_conversations,
            "args": ("TestUser2", pw_hash),
            "expected": "Unread: 1",
            "check": lambda r: ("Unread: 1" in r)
        },
        {
            "description": "TestUser2 requests 5 messages (should error if unread=1 => too many)",
            "function": client.read_convo,
            "args": ("TestUser2", pw_hash, "TestUser1", "5"),
            "expected": "ERROR",
            "check": lambda r: "ERROR" in r
        },
        {
            "description": "TestUser2 asks for 'a' messages (invalid number => 'n must be an integer')",
            "function": client.read_convo,
            "args": ("TestUser2", pw_hash, "TestUser1", "a"),
            "expected": "ERROR",
            "check": lambda r: "ERROR" in r
        },
        {
            "description": "TestUser2 reads 1 more message (should read '3')",
            "function": client.read_convo,
            "args": ("TestUser2", pw_hash, "TestUser1", "1"),
            "expected": "3",
            "check": lambda r: ("3" in r)
        },
        # LIVE MESSAGE TESTS
        {
            "description": "TestUser2 sends a message to TestUser1 saying 'hello'",
            "function": client.send_message,
            "args": ("TestUser2", pw_hash, "TestUser1", "hello"),
            "expected": "OK: Message sent with id",
            "check": lambda r: "OK: Message sent" in r
        },
        {
            "description": "TestUser1 polls conversation with TestUser2 (should get 'hello')",
            "function": client.poll_convo,
            "args": ("TestUser1", pw_hash, "TestUser2"),
            "expected": "hello",
            "check": lambda r: ("hello" in r)
        },
        # DELETION CHECKS
        {
            "description": "Delete TestUser2 account",
            "function": client.delete_account,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Account deleted",
            "check": lambda r: ("OK: Account deleted" in r)
        },
        {
            "description": "TestUser1 checks convos (should not list TestUser2)",
            "function": client.list_conversations,
            "args": ("TestUser1", pw_hash),
            "expected": "TestUser2 should not appear",
            "check": lambda r: ("TestUser2" not in r)
        },
        {
            "description": "Create TestUser2 account again",
            "function": client.create_account,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Account created",
            "check": lambda r: ("OK:" in r and "created" in r)
        },
        {
            "description": "Check chat history between TestUser1 and TestUser2 (should be empty)",
            "function": client.read_full_convo,
            "args": ("TestUser1", pw_hash, "TestUser2", "50"),
            "expected": "No messages",
            "check": lambda r: ("No messages" in r)
        },
        {
            "description": "Delete TestUser2 account",
            "function": client.delete_account,
            "args": ("TestUser2", pw_hash),
            "expected": "OK: Account deleted",
            "check": lambda r: ("OK: Account deleted" in r)
        },
        {
            "description": "Delete TestUser1 account",
            "function": client.delete_account,
            "args": ("TestUser1", pw_hash),
            "expected": "OK: Account deleted",
            "check": lambda r: ("OK: Account deleted" in r)
        }
    ]

    for i, test in enumerate(tests, start=1):
        desc = test["description"]
        func = test.get("function")
        if func is None:
            # Possibly the "Capture ID of the SQL injection message" step
            # We'll handle capturing from the previous test's result
            # The previous test was "TestUser1 sends TestUser2 a SQL injection..."
            # We'll parse the ID "OK: Message sent with id 123"
            # Then call delete_message
            # We can do it carefully:
            prev_test = tests[i-2]  # the injection test is i-2 in the list
            print(f"Test {i}: {desc}")
            if prev_test and prev_test.get("description") and "SQL injection attack" in prev_test["description"]:
                # parse last result from that test
                # we can store results in some data structure; let's do a quick hack:
                # We'll re-run that test's function to get result again, or store them
                # Instead let's store the result in global_sql_id if we didn't do it yet
                # But we'd need the result from the prior step.
                # For simplicity, let's skip the actual re-check. We'll just assume it succeeded.
                # We'll parse the ID from the test if it is already known
                # We can't re-run it because it might create a new message
                # So let's store results as we go. We'll do a quick approach:
                print("Skipping capturing ID in a one-pass approach. (You can store the ID in a global if you do a two-pass.)")
                print_result(i, desc, "Captured ID => Deleted", "Not Implemented", False)
            else:
                print_result(i, desc, "Should capture ID from prior test", "No prior test found", False)
            continue

        # normal test
        test_num_str = f"{i}"
        print(f"Running Test {test_num_str}: {desc}")
        args = test["args"]
        expected = test["expected"]
        checker = test["check"]

        result = func(*args)
        # If it's the SQL injection test, we parse out the ID
        if "SQL injection attack under 256 chars" in desc and "OK: Message sent with id" in result:
            m = re.search(r"with id (\d+)", result)
            if m:
                global_sql_id = m.group(1)
                # Next test is "Capture ID of the SQL injection message"
                # So we can fill that step with a function that calls DeleteMessage
                # We'll do it manually
                if i+1 <= len(tests):
                    next_test = tests[i]  # i is 1-based, so test[i] is the next
                    if "Capture ID" in next_test["description"]:
                        def delete_sql_injection():
                            dresp = client.delete_message("TestUser1", pw_hash, global_sql_id)
                            return dresp
                        next_test["function"] = delete_sql_injection
                        next_test["args"] = ()
                        next_test["expected"] = "OK: Deleted message ids"
                        next_test["check"] = lambda r: ("OK:" in r and "Deleted message ids" in r)

        success = checker(result)
        print_result(test_num_str, desc, expected, result, success)
        if success:
            passed_tests += 1

    total_tests = len(tests)
    summary = f"{passed_tests}/{total_tests} tests passed."
    if passed_tests == total_tests:
        print(f"{GREEN}{summary}{RESET}")
    else:
        print(f"{RED}{summary}{RESET}")


if __name__ == "__main__":
    print("Starting server_grpc.py...")
    server_proc = subprocess.Popen(SERVER_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)  # wait for the server to start

    try:
        run_tests()
    finally:
        server_proc.terminate()
        server_proc.wait()
        print("Server terminated.")
