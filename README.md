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
from scwkms import client
...
```

## Examples

Examples are present in [./examples](./examples). To run them, you need to
create a Key in Scaleway's Key Manager and retrieve its ID. Then create the
following environments variables:
```sh
export SCW_ACCESS_KEY="<access-key>"
export SCW_SECRET_KEY="<secret-key>"
export SCW_DEFAULT_ORGANIZATION_ID="<organization-id>"
export SCW_DEFAULT_PROJECT_ID="<project-id>"
export SCW_DEFAULT_REGION="<region>"
export SCW_API_URL="<api-url>"
export SCW_KMS_KEY_ID="<key-id>"
```

To run [encrypt_decrypt.py](./examples/encrypt_decrypt.py):
```sh
python3 ./examples/encrypt_decrypt.py
```
