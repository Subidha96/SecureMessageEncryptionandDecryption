



import unittest
from securemessage import ModernEncryptionApp  # Replace with the actual file/module name


class TestEncryptionApp(unittest.TestCase):
    
    def setUp(self):
        """Create an instance of the app before each test"""
        self.app = ModernEncryptionApp()
        self.test_message = "Hello, World!"
        self.test_password = "MyS@ecretMessage123"
        self.invalid_password = "WrongPassword"
    
    def test_hash_password(self):
        """Test password hashing"""
        hashed_password = self.app.hash_password(self.test_password)
        self.assertIsInstance(hashed_password, str)
        self.assertEqual(len(hashed_password), 64)  # SHA-256 produces a 64-character hash
    
    def test_encrypt_success(self):
        """Test encryption with correct password"""
        encrypted = self.app.encrypt(self.test_message, self.test_password)
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(encrypted, self.test_message)  # The encrypted message should differ from the original
    




    def test_decrypt_success(self):
        """Test decryption with correct password"""
        encrypted = self.app.encrypt(self.test_message, self.test_password)
        decrypted = self.app.decrypt(encrypted, self.test_password)
        self.assertEqual(decrypted, self.test_message)  # Decrypted message should match the original
    
    def test_encrypt_invalid_password(self):
        """Test encryption with incorrect password"""
        encrypted = self.app.encrypt(self.test_message, self.invalid_password)
        self.assertIsNone(encrypted)  # Encryption should fail with wrong password
    
    def test_decrypt_invalid_password(self):
        """Test decryption with incorrect password"""
        encrypted = self.app.encrypt(self.test_message, self.test_password)
        decrypted = self.app.decrypt(encrypted, self.invalid_password)
        self.assertIsNone(decrypted)  # Decryption should fail with wrong password
    
    def test_decrypt_with_invalid_data(self):
        """Test decryption with corrupted data"""
        corrupted_data = "InvalidBase64Data!"
        decrypted = self.app.decrypt(corrupted_data, self.test_password)
        self.assertIsNone(decrypted)  # Decryption should fail with invalid data




if __name__ == "__main__":
    unittest.main()
