#!/usr/bin/env python3

from scaleway_tink.integration.scwkms import client
import base64
import os


def main():
    key_uri = f"scw-kms://{os.getenv('SCW_KMS_KEY_ID')}"
    aead = client.ScwKmsClient(None, None).get_aead(key_uri)

    plaintext = b'message'
    ciphertext = aead.encrypt(plaintext, b'')

    print(f"plaintext:            {plaintext.decode()}")
    print(f"ciphertext in base64: {base64.b64encode(ciphertext).decode()}")
    print(f"decrypt(ciphertext):  {aead.decrypt(ciphertext, b'').decode()}")


main()
