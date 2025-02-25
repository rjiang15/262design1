#!/usr/bin/env python3
import argparse
import time
from concurrent import futures
import grpc
import chat_pb2
import chat_pb2_grpc
import sqlite3
import os

# --- Database setup (same as before) ---
db_path = os.path.join(os.path.dirname(__file__), "server.db")
conn = sqlite3.connect(db_path, check_same_thread=False)
cursor = conn.cursor()

# Create tables if they don't exist.
cursor.execute('''
CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    logged_in INTEGER DEFAULT 0
)
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    content TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    FOREIGN KEY(recipient) REFERENCES accounts(username)
)
''')
conn.commit()

def display_db_contents():
    """Helper function to display all contents of the database."""
    print("----- Database Contents -----")
    print("Accounts:")
    for row in cursor.execute("SELECT * FROM accounts"):
        print(row)
    print("\nMessages:")
    for row in cursor.execute("SELECT * FROM messages"):
        print(row)
    print("----- End of Database Contents -----")

# --- Your original command-processing logic, modified to assume version has been removed ---
def process_command(command):
    # Now command is the remainder after removing the version.
    tokens = command.split()
    if not tokens:
        return "ERROR: Empty command"
    
    cmd = tokens[0].upper()
    delim = "|||"
    
    if cmd == "SHOW_DB":
        display_db_contents()
        return "OK: Database contents displayed on server console"
    
    elif cmd == "LIST":
        pattern = "%"
        offset = 0
        limit = 10
        if len(tokens) > 1:
            pattern = tokens[1]
            if "%" not in pattern:
                pattern = "%" + pattern + "%"
        if len(tokens) > 2:
            try:
                offset = int(tokens[2])
            except ValueError:
                return "ERROR: offset must be an integer"
        if len(tokens) > 3:
            try:
                limit = int(tokens[3])
            except ValueError:
                return "ERROR: limit must be an integer"
        cursor.execute("SELECT username FROM accounts WHERE username LIKE ? LIMIT ? OFFSET ?", (pattern, limit, offset))
        rows = cursor.fetchall()
        if not rows:
            return "OK: No accounts found"
        cursor.execute("SELECT COUNT(*) FROM accounts WHERE username LIKE ?", (pattern,))
        total = cursor.fetchone()[0]
        response_lines = [f"Total accounts matching: {total}", "Accounts:"]
        for row in rows:
            response_lines.append(row[0])
        return "\n".join(response_lines)
    
    # (Implement other commands similar to your original code.)
    # For brevity, here we only implement a couple of commands.
    elif cmd == "CREATE":
        if len(tokens) != 3:
            return "ERROR: Usage: CREATE username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            return "ERROR: Account already exists"
        cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (username, username))
        cursor.execute("INSERT INTO accounts (username, password, logged_in) VALUES (?, ?, 0)", (username, hashed_password))
        conn.commit()
        return "OK: Account created"
    
    elif cmd == "LOGIN":
        if len(tokens) != 3:
            return "ERROR: Usage: LOGIN username hashed_password"
        username, hashed_password = tokens[1], tokens[2]
        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return "ERROR: Account does not exist"
        if row[0] != hashed_password:
            return "ERROR: Incorrect password"
        cursor.execute("UPDATE accounts SET logged_in = 1 WHERE username = ?", (username,))
        conn.commit()
        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0", (username,))
        count = cursor.fetchone()[0]
        print(f"User {username} logged in at {args.host}:{args.port}")
        return f"OK: Login successful, unread messages: {count}"
    
    # ... (Add all other commands following your original logic.)
    else:
        return "ERROR: Unknown command"

# --- gRPC Service Implementation ---
class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):
    def ProcessCommand(self, request, context):
        # Check protocol version.
        if request.version != "1.0":
            return chat_pb2.CommandResponse(
                version="1.0",
                status="ERROR",
                message="Unsupported protocol version"
            )
        # Process the command.
        result = process_command(request.command)
        status = "OK" if result.startswith("OK:") else "ERROR"
        return chat_pb2.CommandResponse(
            version="1.0",
            status=status,
            message=result
        )

def serve():
    parser = argparse.ArgumentParser(description="Start the gRPC Chat Server.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50051, help="Server port (default: 50051)")
    args = parser.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServiceServicer(), server)
    server.add_insecure_port(f"{args.host}:{args.port}")
    server.start()
    print(f"gRPC server running on {args.host}:{args.port}")
    try:
        while True:
            time.sleep(86400)  # Run forever
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == "__main__":
    from concurrent import futures  # Moved here to avoid import order issues.
    serve()
