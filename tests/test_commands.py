import unittest
from server.server import process_command, accounts  # Import the function and the accounts dict

class TestAccountCommands(unittest.TestCase):
    def setUp(self):
        # Reset the accounts dict before each test.
        accounts.clear()

    def test_create_account(self):
        response = process_command("CREATE alice abc123hash")
        self.assertEqual(response, "OK: Account created")
        self.assertIn("alice", accounts)

    def test_create_existing_account(self):
        process_command("CREATE alice abc123hash")
        response = process_command("CREATE alice abc123hash")
        self.assertTrue("ERROR" in response)

    def test_login_nonexistent(self):
        response = process_command("LOGIN bob somehash")
        self.assertTrue("ERROR" in response)

    def test_login_wrong_password(self):
        process_command("CREATE alice abc123hash")
        response = process_command("LOGIN alice wronghash")
        self.assertTrue("ERROR" in response)

    def test_delete_account(self):
        process_command("CREATE alice abc123hash")
        response = process_command("DELETE alice abc123hash")
        self.assertEqual(response, "OK: Account deleted")
        self.assertNotIn("alice", accounts)

if __name__ == "__main__":
    unittest.main()
