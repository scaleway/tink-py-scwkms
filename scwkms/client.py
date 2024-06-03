import base64

import tink
from tink import aead

from typing import Optional

from scaleway import Client
from scaleway.key_manager.v1alpha1.api import KeyManagerV1Alpha1API
from scaleway_core.api import ScalewayException

SCW_KEYURI_PREFIX = 'scw-kms://'


def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_to_bytes(data: str) -> bytes:
    return base64.b64decode(data)


class _ScwKmsAead(aead.Aead):
    """Implements the Aead interface for SCW KMS."""

    def __init__(self, client: KeyManagerV1Alpha1API, key_id: str) -> None:
        if not key_id:
            raise tink.TinkError('key_id cannot be null.')
        if not client:
            raise tink.TinkError('client cannot be null.')
        self.client = client
        self.key_id = key_id

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        try:
            response = self.client.encrypt(
                key_id=self.key_id,
                plaintext=bytes_to_b64(plaintext),
                associated_data=bytes_to_b64(associated_data))

            return b64_to_bytes(response.ciphertext)
        except ScalewayException as e:
            raise tink.TinkError(e)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        try:
            response = self.client.decrypt(
                key_id=self.key_id,
                ciphertext=bytes_to_b64(ciphertext),
                associated_data=bytes_to_b64(associated_data))

            return b64_to_bytes(response.plaintext)
        except ScalewayException as e:
            raise tink.TinkError(e)


class ScwKmsClient(tink.KmsClient):
    """Basic SCW client for AEAD."""

    def __init__(self, key_uri: Optional[str],
                 credentials_path: Optional[str]) -> None:
        """Creates a new ScwKmsClient that is bound to the key specified in 'key_uri'.

            Uses the specified credentials when communicating with the KMS.

            Args:
              key_uri: The URI of the key the client should be bound to. If it is None
                  or empty, then the client is not bound to any particular key.
              credentials_path: Path to the file with the access credentials. If it is
                  None or empty, then default credentials will be used.

            Raises:
              ValueError: If the path or filename of the credentials is invalid.
              TinkError: If the key uri is not valid.
        """
        if not key_uri:
            self._key_uri = None
        elif key_uri.startswith(SCW_KEYURI_PREFIX):
            self._key_uri = key_uri
        else:
            raise tink.TinkError('Invalid uri_prefix.')
        if not credentials_path:
            self._client = KeyManagerV1Alpha1API(
                Client.from_config_file_and_env())
            return
        self._client = KeyManagerV1Alpha1API(
            Client.from_config_file_and_env(filepath=credentials_path))

    def does_support(self, key_uri: str) -> bool:
        """Returns true if this client supports KMS key specified in 'key_uri'.

        Args:
          key_uri: URI of the key to be checked.

        Returns:
          A boolean value which is true if the key is supported and false otherwise.
        """
        if not self._key_uri:
            return key_uri.startswith(SCW_KEYURI_PREFIX)
        return key_uri == self._key_uri

    def get_aead(self, key_uri: str) -> aead.Aead:
        """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

        Args:
          key_uri: URI of the key which should be used.

        Returns:
          An Aead object.
        """
        if not self.does_support(key_uri):
            if self._key_uri:
                raise tink.TinkError(
                    'This client is bound to %s and cannot use key %s.' %
                    (self._key_uri, key_uri))
            raise tink.TinkError('Invalid key_uri.')

        key_id = key_uri[len(SCW_KEYURI_PREFIX):]
        return _ScwKmsAead(self._client, key_id)

    @classmethod
    def register_client(cls, key_uri: Optional[str],
                        credentials_path: Optional[str]) -> None:
        """Add a new KMS client to the global list of KMS clients.

        This function should only be called on startup and not on every operation.

        In many cases, it is not necessary to register the client. For example,
        you can create a KMS AEAD with
        kms_aead = scwkms.SCWKmsClient(key_uri, credentials_path).get_aead(key_uri)
        and then use it to encrypt or to create an envelope AEAD using aead.KmsEnvelopeAead.

        Args:
            key_uri: Optional key URI. If set, the registered client will only
              handle that key URI. If not set, then the client will handle all SCW
              KMS key URIs.
            credentials_path: Optional path to the credentials file. If it is not
              set, the default credentials are used.
        """
        tink.register_kms_client(ScwKmsClient(key_uri, credentials_path))
