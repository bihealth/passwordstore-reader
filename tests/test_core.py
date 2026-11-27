from unittest.mock import MagicMock, mock_open, patch

import pytest

from passwordstore_reader import PasswordStore


class TestPasswordStore:
    """Tests for the PasswordStore class."""

    def test_init_with_explicit_dir(self) -> None:
        """Test initialization with explicit password_store_dir."""
        with patch("os.path.isdir", return_value=True):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            assert store.password_store_dir == "/home/user/.password-store"

    def test_init_with_env_variable(self) -> None:
        """Test initialization using PASSWORD_STORE_DIR environment variable."""
        with patch.dict("os.environ", {"PASSWORD_STORE_DIR": "/custom/pass/dir"}):
            with patch("os.path.isdir", return_value=True):
                store = PasswordStore()
                assert store.password_store_dir == "/custom/pass/dir"

    def test_init_explicit_dir_overrides_env(self) -> None:
        """Test that explicit directory overrides environment variable."""
        with patch.dict("os.environ", {"PASSWORD_STORE_DIR": "/env/dir"}):
            with patch("os.path.isdir", return_value=True):
                store = PasswordStore(password_store_dir="/explicit/dir")
                assert store.password_store_dir == "/explicit/dir"

    def test_init_raises_error_when_no_dir_provided(self) -> None:
        """Test that initialization raises error when no directory is set."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError) as exc_info:
                PasswordStore()
            assert "password_store_dir not set" in str(exc_info.value)

    def test_init_raises_error_when_empty_string_provided(self) -> None:
        """Test that initialization raises error when empty string is provided."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError) as exc_info:
                PasswordStore(password_store_dir="")
            assert "password_store_dir not set" in str(exc_info.value)

    def test_init_raises_value_error_for_nonexistent_dir(self) -> None:
        """Test that a store dir that does not exist is rejected with ValueError."""
        with (
            patch("os.path.isdir", return_value=False),
            patch("os.path.isfile", return_value=False),
        ):
            with pytest.raises(ValueError) as exc_info:
                PasswordStore(password_store_dir="/home/user/.password-store")
            assert "does not point to a directory or file" in str(exc_info.value)

    def test_show_raises_value_error_for_nonexistent_entry(self) -> None:
        """Test that an entry without a .gpg file is rejected with ValueError."""
        store_dir = "/home/user/.password-store"
        with (
            patch("passwordstore_reader.core.gnupg.GPG"),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", side_effect=lambda path: path == store_dir),
            patch("os.path.isfile", return_value=False),
        ):
            store = PasswordStore(password_store_dir=store_dir)
            with pytest.raises(ValueError) as exc_info:
                store.show("nonexistent")
            assert "does not point to a directory or file" in str(exc_info.value)

    def test_successful_password_retrieval(self) -> None:
        """Test successfully retrieving a password."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = True
        mock_decrypted.data = b"my_secret_password\n"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            password = store.show("email/work")
            assert password == "my_secret_password"
            mock_gpg.decrypt_file.assert_called_once()

    def test_password_with_whitespace_stripped(self) -> None:
        """Test that whitespace is properly stripped from password."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = True
        mock_decrypted.data = b"  password_with_spaces  \n\n"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            password = store.show("test")
            assert password == "password_with_spaces"

    def test_nonexistent_entry_raises_error(self) -> None:
        """Test that a nonexistent entry raises RuntimeError."""
        with (
            patch("passwordstore_reader.core.gnupg.GPG"),
            patch("builtins.open", side_effect=FileNotFoundError("No such file")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            with pytest.raises(FileNotFoundError):
                store.show("nonexistent")

    def test_multiline_password_allowed(self) -> None:
        """Test that legitimate multiline passwords work (without tree characters)."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = True
        mock_decrypted.data = b"line1\nline2\nline3"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            password = store.show("multiline-entry")
            assert password == "line1\nline2\nline3"

    def test_empty_entry_name(self) -> None:
        """Test behavior with empty entry name."""
        with patch("os.path.isdir", return_value=True):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            with pytest.raises(RuntimeError) as exc_info:
                store.show("")

            assert "Entry name cannot be empty" in str(exc_info.value)

    def test_entry_with_special_characters(self) -> None:
        """Test entry names with special characters are rejected by the validator."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = True
        mock_decrypted.data = b"secret123"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            with pytest.raises(ValueError) as exc_info:
                store.show("email/user@example.com")
            assert "Invalid path" in str(exc_info.value)

    def test_decryption_failure_raises_error(self) -> None:
        """Test that decryption failure raises RuntimeError."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = False
        mock_decrypted.status = "decryption failed"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")),
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/home/user/.password-store")
            with pytest.raises(RuntimeError) as exc_info:
                store.show("test")
            assert "Failed to decrypt password file for entry 'test'" in str(exc_info.value)
            assert "decryption failed" in str(exc_info.value)

    def test_password_store_dir_used_in_file_path(self) -> None:
        """Test that PASSWORD_STORE_DIR is correctly used in file path."""
        mock_decrypted = MagicMock()
        mock_decrypted.ok = True
        mock_decrypted.data = b"password"

        mock_gpg = MagicMock()
        mock_gpg.decrypt_file.return_value = mock_decrypted

        with (
            patch("passwordstore_reader.core.gnupg.GPG", return_value=mock_gpg),
            patch("builtins.open", mock_open(read_data=b"encrypted_data")) as m,
            patch("getpass.getpass", return_value="dummy_pass"),
            patch("os.path.isdir", return_value=True),
        ):
            store = PasswordStore(password_store_dir="/custom/store/path")
            store.show("test")
            m.assert_called_once_with("/custom/store/path/test.gpg", "rb")
