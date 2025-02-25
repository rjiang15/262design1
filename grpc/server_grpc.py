#!/usr/bin/env python3
import argparse
import sqlite3
import os
from concurrent import futures
import grpc
from google.protobuf import empty_pb2

import chat_pb2
import chat_pb2_grpc

# We'll just define a function to ensure the database/tables exist once at startup
def initialize_database(db_path):
    # Create a temporary connection for table creation
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
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
    conn.close()

# Path to your database
db_path = os.path.join(os.path.dirname(__file__), "server.db")
initialize_database(db_path)  # Ensure tables exist

def _show_db_contents():
    """
    Return lines describing DB content, replicating SHOW_DB command output,
    but each call uses a fresh DB connection.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    lines = []
    lines.append("----- Database Contents -----")
    lines.append("Accounts:")
    for row in cursor.execute("SELECT * FROM accounts"):
        lines.append(str(row))
    lines.append("\nMessages:")
    for row in cursor.execute("SELECT * FROM messages"):
        lines.append(str(row))
    lines.append("----- End of Database Contents -----")

    conn.close()
    return lines


class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):

    def ShowDB(self, request, context):
        lines = _show_db_contents()
        return chat_pb2.ShowDBResponse(lines=lines)

    def List(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            pattern = request.pattern
            if not pattern:
                pattern = "%"
            if "%" not in pattern:
                pattern = f"%{pattern}%"

            offset = request.offset
            limit = request.limit

            cursor.execute(
                "SELECT username FROM accounts WHERE username LIKE ? LIMIT ? OFFSET ?",
                (pattern, limit, offset)
            )
            rows = cursor.fetchall()
            if not rows:
                conn.close()
                return chat_pb2.ListResponse(
                    status="OK",
                    message="No accounts found",
                    total_count=0,
                    accounts=[]
                )

            cursor.execute(
                "SELECT COUNT(*) FROM accounts WHERE username LIKE ?",
                (pattern,)
            )
            total = cursor.fetchone()[0]
            account_list = [r[0] for r in rows]

            conn.close()
            return chat_pb2.ListResponse(
                status="OK",
                message=f"Total accounts matching: {total}",
                total_count=total,
                accounts=account_list
            )
        except Exception as e:
            conn.close()
            return chat_pb2.ListResponse(
                status="ERROR",
                message=str(e),
                total_count=0,
                accounts=[]
            )

    def ListConversations(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.ListConversationsResponse()
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.ListConversationsResponse()

        cursor.execute("""
            SELECT partner FROM (
                SELECT sender as partner FROM messages WHERE recipient = ?
                UNION
                SELECT recipient as partner FROM messages WHERE sender = ? AND recipient <> ?
            ) ORDER BY partner ASC
        """, (username, username, username))
        partners = cursor.fetchall()
        conversations = []
        total_unread = 0
        for (partner,) in partners:
            # skip if account doesn't exist
            cursor.execute("SELECT COUNT(*) FROM accounts WHERE username = ?", (partner,))
            if cursor.fetchone()[0] == 0:
                continue
            cursor.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender = ? AND read = 0",
                (username, partner)
            )
            unread = cursor.fetchone()[0]
            total_unread += unread

            cursor.execute("""
                SELECT sender, content FROM messages
                WHERE (recipient = ? AND sender = ?) OR (recipient = ? AND sender = ?)
                ORDER BY id DESC LIMIT 1
            """, (username, partner, partner, username))
            last = cursor.fetchone()
            last_message = ""
            if last:
                last_message = f"{last[0]}: {last[1]}"

            conversations.append(
                chat_pb2.Conversation(partner=partner, unread=unread, last_message=last_message)
            )

        conn.close()
        return chat_pb2.ListConversationsResponse(
            total_unread=total_unread,
            conversations=conversations
        )

    def ReadInbox(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        n = request.n

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.ReadInboxResponse(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.ReadInboxResponse(status="ERROR", message="Authentication failed")

        cursor.execute(
            "SELECT id, sender, content FROM messages WHERE recipient = ? ORDER BY id ASC LIMIT ?",
            (username, n)
        )
        rows = cursor.fetchall()
        if not rows:
            conn.close()
            return chat_pb2.ReadInboxResponse(status="OK", message="No messages")

        msg_ids = [r[0] for r in rows]
        qmarks = ",".join("?"*len(msg_ids))
        cursor.execute(f"UPDATE messages SET read = 1 WHERE id IN ({qmarks})", msg_ids)
        conn.commit()

        messages = []
        for (mid, sender, content) in rows:
            messages.append(chat_pb2.Message(id=mid, sender=sender, content=content))

        conn.close()
        return chat_pb2.ReadInboxResponse(
            status="OK",
            message="",
            messages=messages
        )

    def ReadConvo(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        other_user = request.other_user
        n = request.n

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.ReadConvoResponse(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.ReadConvoResponse(status="ERROR", message="Authentication failed")

        # Count how many unread
        cursor.execute("""
            SELECT COUNT(*) FROM messages
            WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
              AND read = 0
        """, (username, other_user, other_user, username))
        unread_count = cursor.fetchone()[0]

        if unread_count > 0:
            if n > unread_count:
                conn.close()
                return chat_pb2.ReadConvoResponse(
                    status="ERROR",
                    message=f"The allowed maximum value is {unread_count}. Please try again."
                )
            cursor.execute("""
                SELECT id, sender, content FROM messages
                WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                  AND read = 0
                ORDER BY id ASC LIMIT ?
            """, (username, other_user, other_user, username, n))
        else:
            cursor.execute("""
                SELECT id, sender, content FROM messages
                WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                ORDER BY id ASC LIMIT ?
            """, (username, other_user, other_user, username, n))

        rows = cursor.fetchall()
        if not rows:
            conn.close()
            return chat_pb2.ReadConvoResponse(
                status="OK",
                message=f"No messages in conversation with {other_user}"
            )

        msg_ids = [r[0] for r in rows]
        if msg_ids:
            qmarks = ",".join("?"*len(msg_ids))
            cursor.execute(
                f"UPDATE messages SET read = 1 WHERE id IN ({qmarks}) AND recipient = ?",
                (*msg_ids, username)
            )
            conn.commit()

        messages = []
        for (mid, sender, content) in rows:
            messages.append(chat_pb2.Message(id=mid, sender=sender, content=content))

        conn.close()
        return chat_pb2.ReadConvoResponse(
            status="OK",
            message="",
            messages=messages
        )

    def ReadFullConvo(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        other_user = request.other_user
        n = request.n

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.ReadConvoResponse(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.ReadConvoResponse(status="ERROR", message="Authentication failed")

        cursor.execute("""
            SELECT id, sender, content FROM messages
            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
            ORDER BY id ASC LIMIT ?
        """, (username, other_user, other_user, username, n))
        rows = cursor.fetchall()
        if not rows:
            conn.close()
            return chat_pb2.ReadConvoResponse(
                status="OK",
                message=f"No messages in conversation with {other_user}"
            )

        messages = []
        for (mid, sender, content) in rows:
            messages.append(chat_pb2.Message(id=mid, sender=sender, content=content))

        conn.close()
        return chat_pb2.ReadConvoResponse(
            status="OK",
            message="",
            messages=messages
        )

    def PollConvo(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        other_user = request.other_user

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.PollConvoResponse(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.PollConvoResponse(status="ERROR", message="Authentication failed")

        cursor.execute("""
            SELECT id, sender, content FROM messages
            WHERE recipient = ? AND sender = ? AND read = 0
            ORDER BY id ASC
        """, (username, other_user))
        rows = cursor.fetchall()
        if not rows:
            conn.close()
            return chat_pb2.PollConvoResponse(status="OK", message="No new messages", messages=[])

        msg_ids = [r[0] for r in rows]
        qmarks = ",".join("?"*len(msg_ids))
        cursor.execute(f"UPDATE messages SET read = 1 WHERE id IN ({qmarks})", msg_ids)
        conn.commit()

        messages = []
        for (mid, sender, content) in rows:
            messages.append(chat_pb2.Message(id=mid, sender=sender, content=content))

        conn.close()
        return chat_pb2.PollConvoResponse(status="OK", message="", messages=messages)

    def CreateAccount(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password

        cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account already exists")

        cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (username, username))
        cursor.execute(
            "INSERT INTO accounts (username, password, logged_in) VALUES (?, ?, 0)",
            (username, hashed_password)
        )
        conn.commit()
        conn.close()
        return chat_pb2.Response(status="OK", message="Account created")

    def Login(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Incorrect password")

        cursor.execute("UPDATE accounts SET logged_in = 1 WHERE username = ?", (username,))
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0", (username,))
        count = cursor.fetchone()[0]
        conn.close()
        return chat_pb2.Response(
            status="OK",
            message=f"Login successful, unread messages: {count}"
        )

    def Logout(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Incorrect password")

        cursor.execute("UPDATE accounts SET logged_in = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return chat_pb2.Response(status="OK", message="Logged out")

    def DeleteAccount(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Incorrect password")

        cursor.execute("DELETE FROM accounts WHERE username = ?", (username,))
        cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (username, username))
        conn.commit()
        conn.close()
        return chat_pb2.Response(status="OK", message="Account deleted")

    def SendMessage(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        sender = request.sender
        hashed_password = request.hashed_password
        recipient = request.recipient
        message = request.message

        if len(message) > 256:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Message too long. Maximum allowed is 256 characters.")

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (sender,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Sender account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Sender authentication failed")

        cursor.execute("SELECT * FROM accounts WHERE username = ?", (recipient,))
        if not cursor.fetchone():
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Recipient account does not exist")

        cursor.execute(
            "INSERT INTO messages (recipient, sender, content, read) VALUES (?, ?, ?, 0)",
            (recipient, sender, message)
        )
        msg_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return chat_pb2.Response(status="OK", message=f"Message sent with id {msg_id}")

    def DeleteMessage(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        target = request.message_ids

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Authentication failed")

        if target.upper() == "ALL":
            cursor.execute("SELECT COUNT(*) FROM messages WHERE (recipient = ? OR sender = ?)", (username, username))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM messages WHERE (recipient = ? OR sender = ?)", (username, username))
            conn.commit()
            conn.close()
            return chat_pb2.Response(status="OK", message=f"Deleted all messages ({count} messages)")
        else:
            parts = [x.strip() for x in target.split(",")]
            msg_ids = []
            for p in parts:
                try:
                    msg_ids.append(int(p))
                except ValueError:
                    conn.close()
                    return chat_pb2.Response(status="ERROR", message=f"Message ID '{p}' invalid")
            # check authorization for each
            for mid in msg_ids:
                cursor.execute("SELECT * FROM messages WHERE id = ? AND (recipient = ? OR sender = ?)",
                               (mid, username, username))
                if cursor.fetchone() is None:
                    conn.close()
                    return chat_pb2.Response(
                        status="ERROR",
                        message=f"Message id {mid} not found or not authorized"
                    )
            qmarks = ",".join("?"*len(msg_ids))
            cursor.execute(f"DELETE FROM messages WHERE id IN ({qmarks})", msg_ids)
            conn.commit()
            conn.close()
            return chat_pb2.Response(
                status="OK",
                message=f"Deleted message ids {','.join(map(str, msg_ids))}"
            )

    def MarkRead(self, request, context):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        username = request.username
        hashed_password = request.hashed_password
        msg_id = request.message_id

        cursor.execute("SELECT password FROM accounts WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Account does not exist")
        if row[0] != hashed_password:
            conn.close()
            return chat_pb2.Response(status="ERROR", message="Authentication failed")

        if msg_id.upper() == "ALL":
            cursor.execute("UPDATE messages SET read = 1 WHERE recipient = ? AND read = 0", (username,))
            conn.commit()
            conn.close()
            return chat_pb2.Response(status="OK", message="Marked all messages as read")
        else:
            try:
                mid = int(msg_id)
            except ValueError:
                conn.close()
                return chat_pb2.Response(status="ERROR", message="msg_id must be integer or ALL")
            cursor.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (mid, username))
            if not cursor.fetchone():
                conn.close()
                return chat_pb2.Response(status="ERROR", message="Message id not found or not yours")
            cursor.execute("UPDATE messages SET read = 1 WHERE id = ?", (mid,))
            conn.commit()
            conn.close()
            return chat_pb2.Response(status="OK", message=f"Marked message id {mid} as read")


def serve():
    parser = argparse.ArgumentParser(description="Start the gRPC Chat server.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50051, help="Port (default: 50051)")
    args = parser.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServiceServicer(), server)
    server.add_insecure_port(f"{args.host}:{args.port}")
    print(f"gRPC server listening on {args.host}:{args.port}")
    server.start()
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()
