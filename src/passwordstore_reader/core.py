import getpass
import os

import gnupg

from .validator import validate_path


class PasswordStore:
    """Read access to an existing pass password store.

    Entries are decrypted directly with GnuPG, so the ``pass`` command is not needed.

    Attributes:
        password_store_dir (str): Directory of the password store in use.
    """

    def __init__(self, password_store_dir: str | None = None) -> None:
        """Open the password store in ``password_store_dir``.

        Args:
            password_store_dir (str | None): Directory of the password store. If not given, the
                ``PASSWORD_STORE_DIR`` environment variable is used.

        Raises:
            RuntimeError: If no directory is given and ``PASSWORD_STORE_DIR`` is not set.
            ValueError: If the directory does not exist or its path contains characters other
                than letters, digits, ``.``, ``_``, ``/`` and ``-`` (so no spaces or ``~``).
        """

        self.password_store_dir = password_store_dir or os.environ.get("PASSWORD_STORE_DIR", "")

        if not self.password_store_dir:
            raise RuntimeError(
                "password_store_dir not set. Please provide PASSWORD_STORE_DIR in the "
                "environment or pass a directory to the constructor"
            )

        validate_path(self.password_store_dir)

    def show(self, entry: str) -> str:
        """Decrypt and return an entry, like ``pass show <entry>``.

        Prompts for the GPG key passphrase on every call.

        Args:
            entry (str): Name of the entry, relative to the store and without ``.gpg``,
                e.g. ``example/api_key``.

        Returns:
            str: The decrypted content with leading and trailing whitespace stripped.
            Multi-line entries are returned in full.

        Raises:
            RuntimeError: If the entry name is empty or the entry cannot be decrypted.
            ValueError: If the entry contains disallowed characters, escapes the password
                store directory, or does not exist.
        """
        if not entry:
            raise RuntimeError("Entry name cannot be empty")

        gpg = gnupg.GPG()
        password_store_file = self.password_store_dir + "/" + entry + ".gpg"

        validate_path(password_store_file, self.password_store_dir)

        passphrase = getpass.getpass("Enter gpg key password: ")

        with open(password_store_file, "rb") as fh:
            decrypted_data = gpg.decrypt_file(fh, passphrase=passphrase)

        if not decrypted_data.ok:
            raise RuntimeError(
                f"Failed to decrypt password file for entry '{entry}': {decrypted_data.status}"
            )

        data = decrypted_data.data
        # python-gnupg sets data to bytes on a successful decrypt; '' is only its placeholder.
        assert isinstance(data, bytes)

        return data.decode().strip()
