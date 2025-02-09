import unittest
import threading
from server.server import process_command, conn, cursor

class TestAccountMessagingCommands(unittest.TestCase):
    def setUp(self):
        # Clear the database tables before each test.
        cursor.execute("DELETE FROM accounts")
        cursor.execute("DELETE FROM messages")
        conn.commit()

    # ===== Account management tests =====

    def test_create_existing_account(self):
        response = process_command("CREATE alice hash123")
        self.assertEqual(response, "OK: Account created")
        response2 = process_command("CREATE alice hash123")
        self.assertIn("ERROR", response2)

    def test_create_account_after_deletion(self):
        # Create an account "bob"
        response = process_command("CREATE bob hashbob")
        self.assertEqual(response, "OK: Account created")
        # Create a sender account and send a message to bob.
        process_command("CREATE alice hashalice")
        send_response = process_command("SEND alice hashalice bob Hello Bob")
        self.assertTrue("OK: Message sent" in send_response)
        # Delete bob's account.
        del_response = process_command("DELETE bob hashbob")
        self.assertEqual(del_response, "OK: Account deleted")
        # Recreate bob's account; there should be no old messages.
        response3 = process_command("CREATE bob hashbob")
        self.assertEqual(response3, "OK: Account created")
        read_response = process_command("READ bob hashbob 10")
        self.assertIn("OK: No messages", read_response)

    def test_login_nonexistent(self):
        response = process_command("LOGIN nonexist hash")
        self.assertIn("ERROR", response)

    def test_login_wrong_password(self):
        process_command("CREATE charlie hashcharlie")
        response = process_command("LOGIN charlie wronghash")
        self.assertIn("ERROR", response)

    def test_delete_nonexistent_account(self):
        response = process_command("DELETE nonexist hash")
        self.assertIn("ERROR", response)

    def test_delete_account_when_logged_in(self):
        process_command("CREATE dave hashdave")
        login_response = process_command("LOGIN dave hashdave")
        self.assertIn("OK: Login successful", login_response)
        # Even if logged in, our implementation allows deletion.
        del_response = process_command("DELETE dave hashdave")
        self.assertEqual(del_response, "OK: Account deleted")

    def test_concurrent_creations(self):
        # Use threads to concurrently create accounts with different names.
        results = {}
        def create_account(username, index):
            res = process_command(f"CREATE {username} hash{username}")
            results[index] = res

        threads = []
        for i in range(10):
            t = threading.Thread(target=create_account, args=(f"user{i}", i))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        for i in range(10):
            self.assertEqual(results[i], "OK: Account created")

    def test_concurrent_logins(self):
        process_command("CREATE eve hasheve")
        login_results = []
        def login_account():
            resp = process_command("LOGIN eve hasheve")
            login_results.append(resp)
        threads = []
        for _ in range(5):
            t = threading.Thread(target=login_account)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        for resp in login_results:
            self.assertIn("OK: Login successful", resp)

    # ===== Message tests =====

    def test_send_message_normal(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        response = process_command("SEND sender hashsender receiver Hello")
        self.assertIn("OK: Message sent with id", response)

    def test_send_empty_message(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        response = process_command("SEND sender hashsender receiver ")
        # Even an empty message is processed (resulting in an empty content string).
        self.assertIn("OK: Message sent with id", response)

    def test_send_message_to_nonexistent(self):
        process_command("CREATE sender hashsender")
        response = process_command("SEND sender hashsender nonexist Hello")
        self.assertIn("ERROR", response)

    def test_send_message_attack(self):
        process_command("CREATE attacker hashattacker")
        process_command("CREATE victim hashvictim")
        # Attempt to inject SQL in the message content.
        attack_message = "Hello'); DROP TABLE accounts; --"
        response = process_command(f"SEND attacker hashattacker victim {attack_message}")
        self.assertIn("OK: Message sent with id", response)
        # Ensure the victim account still exists.
        login_response = process_command("LOGIN victim hashvictim")
        self.assertIn("OK: Login successful", login_response)

    def test_send_message_overflow(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        long_message = "A" * 2048  # 2048 characters; our implementation does not enforce a strict limit.
        response = process_command(f"SEND sender hashsender receiver {long_message}")
        self.assertIn("OK: Message sent with id", response)

    def test_send_message_to_self(self):
        process_command("CREATE selfuser hashself")
        response = process_command("SEND selfuser hashself selfuser Hello Self")
        self.assertIn("OK: Message sent with id", response)

    def test_receive_message(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        process_command("SEND sender hashsender receiver HelloReceiver")
        response = process_command("READ receiver hashreceiver 10")
        self.assertIn("HelloReceiver", response)

    def test_read_message_limit(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        # Send 5 messages.
        for i in range(5):
            process_command(f"SEND sender hashsender receiver Message{i}")
        # Request only 3 messages.
        response = process_command("READ receiver hashreceiver 3")
        lines = response.splitlines()
        # Expect exactly 3 lines (each line is one message).
        self.assertEqual(len(lines), 3)
        # Now read the remaining messages.
        response2 = process_command("READ receiver hashreceiver 10")
        lines2 = response2.splitlines()
        self.assertEqual(len(lines2), 2)

    def test_mark_message_as_read(self):
        process_command("CREATE sender hashsender")
        process_command("CREATE receiver hashreceiver")
        process_command("SEND sender hashsender receiver UnreadMsg")
        # Read messages; this call automatically marks them as read.
        response = process_command("READ receiver hashreceiver 10")
        self.assertIn("UnreadMsg", response)
        # Send another message.
        process_command("SEND sender hashsender receiver AnotherMsg")
        # Explicitly mark the first message as read.
        mark_response = process_command("MARK_READ receiver hashreceiver 1")
        self.assertIn("OK: Marked message id 1 as read", mark_response)
        # Reading again should only return the unread message.
        response_after = process_command("READ receiver hashreceiver 10")
        self.assertNotIn("UnreadMsg", response_after)
        self.assertIn("AnotherMsg", response_after)

if __name__ == "__main__":
    unittest.main()
