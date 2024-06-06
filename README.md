# Tink Python Scaleway's Key Manager extension

This is an extension to the [Tink
Python](https://github.com/tink-crypto/tink-py) library that provides support
for Scaleway's Key Manager.

The official documentation is available at https://developers.google.com/tink.

## Installation

Install [poetry](https://python-poetry.org/docs/#installation):
```sh
curl -sSL https://install.python-poetry.org | python3 -
```

Clone the repository, then install the package:
```sh
poetry shell
poetry install
```

You can now import the package in your Python scripts:
```python
from scaleway_tink.integration.scwkms import client
...
```

Check [Scaleway's configuration
documentation](https://www.scaleway.com/en/docs/developer-tools/scaleway-cli/reference-content/scaleway-configuration-file/)
to configure the provider.

## Examples

Examples are present in [./examples](./examples).

To run them, you need to create a Key in Scaleway's Key Manager and retrieve its
ID. Export that ID as an environment variable:
```
export SCW_KMS_KEY_ID="<key-id>"
```

Make sure you have a [configuration file or environment
variables](https://www.scaleway.com/en/docs/developer-tools/scaleway-cli/reference-content/scaleway-configuration-file/)
set. You can now run the examples:
```sh
python3 ./examples/encrypt_decrypt.py
```
