# passwordstore-reader

Small Python library to access passwords from the [pass](https://www.passwordstore.org/) password
manager. This library relies on `gnupg`, so the `pass` command is not required to be able to use an
existing store on systems without this command available. The password store must be however
maintained on a different system with `pass` available.

It also accounts for the case that pinentry is not available on the system which would prevent
`gnupg` from using a password prompt.

## Installation

```bash
# With uv
uv add passwordstore-reader

# With pip
pip install passwordstore-reader
```

## Usage

```python
from passwordstore_reader import PasswordStore

# Create the store, assuming the PASSWORD_STORE_DIR env variable is set.
pwstore = PasswordStore()

# Create the store with a custom password store path.
pwstore = PasswordStore(password_store_dir="./password-store")

# Retrieve a password
password = pwstore.show("example/api_key")
```

`show()` prompts for your GPG key passphrase on every call.

### In pydantic models

If you have a pydantic model that contains credentials, you can define a mixin that you inject into
your model. This would resolve all values in your model that start with `password_store:` to the
path in the password store that follows the keyword and store the password in the value, e.g
`password = "password_store:my/secret/pass"` resolves to whatever password is stored under `pass
my/secret/pass`.

```python
class PasswordStoreMixin:
    """Mixin for configurations that include password store paths."""

    @pydantic.model_validator(mode="before")
    @classmethod
    def resolve_password_store(cls, values):
        if not isinstance(values, dict):
            return values

        def resolve(obj):
            if isinstance(obj, str) and obj.startswith("password_store:"):
                password_store_path = obj[len("password_store:") :]
                return PasswordStore().show(password_store_path)
            return obj

        return {k: resolve(v) for k, v in values.items()}
```

## Requirements

- Python 3.12+

## License

MIT, see [LICENSE](LICENSE).
