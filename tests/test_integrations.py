#!/usr/bin/env python3
import unittest
import subprocess
import time
import socket

class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Define the host and port that will be used by both the server and the tests.
        # These values match the default values of our server if not overridden.
        cls.host = "127.0.0.1"
        cls.port = 54400
        # Start the server as a subprocess with command-line arguments.
        cls.server_proc = subprocess.Popen(
            ["python", "server/server.py", "--host", cls.host, "--port", str(cls.port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give the server some time to start up.
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        # Terminate the server subprocess.
        cls.server_proc.terminate()
        cls.server_proc.wait()

    def send_command(self, command):
        """Helper to send a command to the server and return its response."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall((command + "\n").encode("utf-8"))
            # Increase buffer size if needed.
            data = s.recv(4096).decode("utf-8")
            return data.strip()

    def test_create_and_login(self):
        # Create an account and then log in.
        response = self.send_command("CREATE charlie hashcharlie")
        self.assertEqual(response, "OK: Account created")
        response = self.send_command("LOGIN charlie hashcharlie")
        self.assertTrue("OK: Login successful" in response)

    def test_list_accounts(self):
        # Create several accounts.
        self.send_command("CREATE alice hashalice")
        self.send_command("CREATE bob hashbob")
        self.send_command("CREATE carol hashcarol")
        # List accounts; here we use a pattern (using a wildcard).
        response = self.send_command("LIST % 0 10")
        self.assertIn("alice", response)
        self.assertIn("bob", response)
        self.assertIn("carol", response)

    def test_send_and_read_message(self):
        # Create two accounts.
        self.send_command("CREATE sender hashsender")
        self.send_command("CREATE receiver hashreceiver")
        # Send a message from sender to receiver.
        send_response = self.send_command("SEND sender hashsender receiver HelloWorld")
        self.assertIn("OK: Message sent with id", send_response)
        # Read messages for the receiver.
        read_response = self.send_command("READ receiver hashreceiver 10")
        self.assertIn("HelloWorld", read_response)

if __name__ == "__main__":
    unittest.main()
