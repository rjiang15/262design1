#!/usr/bin/env python3
import grpc
from concurrent import futures
import time
import sqlite3, os
import chat_pb2
import chat_pb2_grpc

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

class ChatServiceServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        db_path = os.path.join(os.path.dirname(__file__), "server_grpc.db")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()
        
    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                logged_in INTEGER DEFAULT 0
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                read INTEGER DEFAULT 0,
                FOREIGN KEY(recipient) REFERENCES accounts(username)
            )
        ''')
        self.conn.commit()

    def CreateAccount(self, request, context):
        self.cursor.execute("SELECT * FROM accounts WHERE username = ?", (request.username,))
        if self.cursor.fetchone() is not None:
            return chat_pb2.CreateAccountResponse(success=False, message="Account already exists")
        self.cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (request.username, request.username))
        self.cursor.execute("INSERT INTO accounts (username, password, logged_in) VALUES (?, ?, 0)", (request.username, request.hashed_password))
        self.conn.commit()
        return chat_pb2.CreateAccountResponse(success=True, message="Account created")
        
    def Login(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.LoginResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.LoginResponse(success=False, message="Incorrect password")
        self.cursor.execute("UPDATE accounts SET logged_in = 1 WHERE username = ?", (request.username,))
        self.conn.commit()
        self.cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0", (request.username,))
        count = self.cursor.fetchone()[0]
        return chat_pb2.LoginResponse(success=True, message=f"Login successful, unread messages: {count}")
        
    def Logout(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.LogoutResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.LogoutResponse(success=False, message="Incorrect password")
        self.cursor.execute("UPDATE accounts SET logged_in = 0 WHERE username = ?", (request.username,))
        self.conn.commit()
        return chat_pb2.LogoutResponse(success=True, message="Logged out")
        
    def DeleteAccount(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.DeleteAccountResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.DeleteAccountResponse(success=False, message="Incorrect password")
        self.cursor.execute("DELETE FROM accounts WHERE username = ?", (request.username,))
        self.cursor.execute("DELETE FROM messages WHERE recipient = ? OR sender = ?", (request.username, request.username))
        self.conn.commit()
        return chat_pb2.DeleteAccountResponse(success=True, message="Account deleted")
        
    def SendMessage(self, request, context):
        if len(request.content) > 256:
            return chat_pb2.SendMessageResponse(success=False, message="Message too long. Maximum allowed is 256 characters.")
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.sender,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.SendMessageResponse(success=False, message="Sender account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.SendMessageResponse(success=False, message="Sender authentication failed")
        self.cursor.execute("SELECT * FROM accounts WHERE username = ?", (request.recipient,))
        if self.cursor.fetchone() is None:
            return chat_pb2.SendMessageResponse(success=False, message="Recipient account does not exist")
        self.cursor.execute("INSERT INTO messages (recipient, sender, content, read) VALUES (?, ?, ?, 0)", 
                            (request.recipient, request.sender, request.content))
        self.conn.commit()
        msg_id = self.cursor.lastrowid
        return chat_pb2.SendMessageResponse(success=True, message=f"Message sent with id {msg_id}")
        
    def ReadMessages(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.ReadMessagesResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.ReadMessagesResponse(success=False, message="Authentication failed")
        self.cursor.execute("SELECT id, sender, content FROM messages WHERE recipient = ? ORDER BY id ASC LIMIT ?", 
                            (request.username, request.n))
        rows = self.cursor.fetchall()
        messages = []
        if not rows:
            return chat_pb2.ReadMessagesResponse(success=True, message="No messages")
        for r in rows:
            messages.append(chat_pb2.Message(id=r[0], sender=r[1], content=r[2]))
        q_marks = ",".join("?" * len([r[0] for r in rows]))
        self.cursor.execute(f"UPDATE messages SET read = 1 WHERE id IN ({q_marks})", [r[0] for r in rows])
        self.conn.commit()
        return chat_pb2.ReadMessagesResponse(success=True, messages=messages, message="Messages read")
    
    def ReadConversation(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.ReadConversationResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.ReadConversationResponse(success=False, message="Authentication failed")
        self.cursor.execute("""
            SELECT COUNT(*) FROM messages
            WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
              AND read = 0
            ORDER BY id ASC
        """, (request.username, request.other_user, request.other_user, request.username))
        unread_count = self.cursor.fetchone()[0]
        if unread_count > 0:
            if request.n > unread_count:
                return chat_pb2.ReadConversationResponse(success=False, message=f"The allowed maximum value is {unread_count}. Please try again.")
            self.cursor.execute("""
                SELECT id, sender, content FROM messages
                WHERE ((sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?))
                  AND read = 0
                ORDER BY id ASC LIMIT ?
            """, (request.username, request.other_user, request.other_user, request.username, request.n))
        else:
            self.cursor.execute("""
                SELECT id, sender, content FROM messages
                WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                ORDER BY id ASC LIMIT ?
            """, (request.username, request.other_user, request.other_user, request.username, request.n))
        rows = self.cursor.fetchall()
        messages = []
        if not rows:
            return chat_pb2.ReadConversationResponse(success=True, message=f"No messages in conversation with {request.other_user}")
        for r in rows:
            messages.append(chat_pb2.Message(id=r[0], sender=r[1], content=r[2]))
        q_marks = ",".join("?" * len([r[0] for r in rows]))
        self.cursor.execute(f"UPDATE messages SET read = 1 WHERE id IN ({q_marks})", [r[0] for r in rows])
        self.conn.commit()
        return chat_pb2.ReadConversationResponse(success=True, messages=messages, message="Conversation messages read")
        
    def PollConversation(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.PollConversationResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.PollConversationResponse(success=False, message="Authentication failed")
        self.cursor.execute("""
            SELECT id, sender, content FROM messages
            WHERE recipient = ? AND sender = ? AND read = 0
            ORDER BY id ASC
        """, (request.username, request.other_user))
        rows = self.cursor.fetchall()
        messages = []
        if not rows:
            return chat_pb2.PollConversationResponse(success=True, message="No new messages")
        for r in rows:
            messages.append(chat_pb2.Message(id=r[0], sender=r[1], content=r[2]))
        q_marks = ",".join("?" * len([r[0] for r in rows]))
        self.cursor.execute(f"UPDATE messages SET read = 1 WHERE id IN ({q_marks})", [r[0] for r in rows])
        self.conn.commit()
        return chat_pb2.PollConversationResponse(success=True, messages=messages, message="New messages polled")
        
    def ListConversations(self, request, context):
        self.cursor.execute("SELECT password FROM accounts WHERE username = ?", (request.username,))
        row = self.cursor.fetchone()
        if row is None:
            return chat_pb2.ListConversationsResponse(success=False, message="Account does not exist")
        if row[0] != request.hashed_password:
            return chat_pb2.ListConversationsResponse(success=False, message="Incorrect password")
        self.cursor.execute("""
            SELECT partner FROM (
                SELECT sender as partner FROM messages WHERE recipient = ?
                UNION
                SELECT recipient as partner FROM messages WHERE sender = ? AND recipient <> ?
            ) ORDER BY partner ASC
        """, (request.username, request.username, request.username))
        partners = self.cursor.fetchall()
        conversations = []
        total_unread = 0
        for (partner,) in partners:
            self.cursor.execute("SELECT COUNT(*) FROM accounts WHERE username = ?", (partner,))
            if self.cursor.fetchone()[0] == 0:
                continue
            self.cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender = ? AND read = 0", (request.username, partner))
            unread = self.cursor.fetchone()[0]
            total_unread += unread
            self.cursor.execute("""
                SELECT sender, content FROM messages
                WHERE (recipient = ? AND sender = ?) OR (recipient = ? AND sender = ?)
                ORDER BY id DESC LIMIT 1
            """, (request.username, partner, partner, request.username))
            last = self.cursor.fetchone()
            last_message = f"{last[0]}: {last[1]}" if last else ""
            conversations.append(chat_pb2.Conversation(partner=partner, unread=unread, last_message=last_message))
        return chat_pb2.ListConversationsResponse(success=True, total_unread=total_unread, conversations=conversations, message=f"Total unread messages: {total_unread}")
        
    def ListAccounts(self, request, context):
        pattern = request.pattern
        if "%" not in pattern:
            pattern = "%" + pattern + "%"
        offset = request.offset
        limit = request.limit
        self.cursor.execute("SELECT username FROM accounts WHERE username LIKE ? LIMIT ? OFFSET ?", (pattern, limit, offset))
        rows = self.cursor.fetchall()
        if not rows:
            return chat_pb2.ListAccountsResponse(success=True, message="No accounts found")
        self.cursor.execute("SELECT COUNT(*) FROM accounts WHERE username LIKE ?", (pattern,))
        total = self.cursor.fetchone()[0]
        accounts_list = [row[0] for row in rows]
        return chat_pb2.ListAccountsResponse(success=True, total_accounts=total, accounts=accounts_list, message=f"Total accounts matching: {total}")
        
def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServiceServicer(), server)
    server.add_insecure_port(f"{HOST}:{PORT}")
    server.start()
    print(f"gRPC server listening on {HOST}:{PORT}")
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)
        
if __name__ == "__main__":
    serve()
