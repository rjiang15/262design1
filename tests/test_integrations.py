import unittest
import subprocess
import time
import socket

HOST = "127.0.0.1"
PORT = 54400

class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server in a subprocess.
        cls.server_proc = subprocess.Popen(
            ["python", "server/server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give the server a moment to start up.
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.server_proc.terminate()
        cls.server_proc.wait()

    def send_command(self, command):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall((command + "\n").encode("utf-8"))
            data = s.recv(1024).decode("utf-8")
            return data.strip()

    def test_create_and_login(self):
        # Create account
        response = self.send_command("CREATE charlie hashcharlie")
        self.assertEqual(response, "OK: Account created")
        # Login with correct password
        response = self.send_command("LOGIN charlie hashcharlie")
        self.assertTrue("OK: Login successful" in response)

if __name__ == "__main__":
    unittest.main()
