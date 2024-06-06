from . import client
import os
import unittest


class TestScwKmsClient(unittest.TestCase):

    def setUp(self):
        key_uri = f"scw-kms://{os.getenv('SCW_KMS_KEY_ID')}"
        self.aead = client.ScwKmsClient(None, None).get_aead(key_uri)

    def test_encrypt_decrypt(self):
        plaintext = b'message'
        ciphertext = self.aead.encrypt(plaintext, b'')
        self.assertEqual(plaintext, self.aead.decrypt(ciphertext, b''))

    def test_encrypt_decrypt_with_associated_data(self):
        plaintext = b'message'
        ad = b'data'
        ciphertext = self.aead.encrypt(plaintext, ad)
        self.assertEqual(plaintext, self.aead.decrypt(ciphertext, ad))


if __name__ == '__main__':
    unittest.main()
