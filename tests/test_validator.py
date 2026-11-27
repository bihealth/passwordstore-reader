import os
from unittest.mock import MagicMock, patch

import pytest

from passwordstore_reader.validator import ValidPath, validate_path


class TestValidatePath:
    @patch.object(os.path, "isfile", return_value=True)
    @patch.object(os.path, "isdir", return_value=False)
    def test_valid_path(self, mock_isdir: MagicMock, mock_isfile: MagicMock) -> None:
        # Should not raise for a safe path
        path = "/home/user/.password-store/email/work.gpg"
        result = validate_path(path)
        assert isinstance(result, ValidPath)

    @patch.object(os.path, "isfile", return_value=False)
    @patch.object(os.path, "isdir", return_value=False)
    def test_path_with_dotdot(self, mock_isdir: MagicMock, mock_isfile: MagicMock) -> None:
        # Should raise for path traversal
        with pytest.raises(ValueError) as exc_info:
            validate_path("/home/user/.password-store/../etc/passwd")
        assert "Path traversal attempt" in str(exc_info.value)

    @patch.object(os.path, "isfile", return_value=False)
    @patch.object(os.path, "isdir", return_value=False)
    def test_path_with_backslash(self, mock_isdir: MagicMock, mock_isfile: MagicMock) -> None:
        # Should raise for backslash
        with pytest.raises(ValueError) as exc_info:
            validate_path("/home/user/.password-store\\evil.gpg")
        assert "Path traversal attempt" in str(exc_info.value)

    @patch.object(os.path, "isfile", return_value=False)
    @patch.object(os.path, "isdir", return_value=False)
    def test_path_with_invalid_chars(self, mock_isdir: MagicMock, mock_isfile: MagicMock) -> None:
        # Should raise for invalid characters (e.g., @)
        with pytest.raises(ValueError) as exc_info:
            validate_path("/home/user/.password-store/email/user@example.com.gpg")
        assert "Invalid path" in str(exc_info.value)

    @patch.object(os.path, "isfile", return_value=False)
    @patch.object(os.path, "isdir", return_value=False)
    def test_empty_path(self, mock_isdir: MagicMock, mock_isfile: MagicMock) -> None:
        # Should raise for empty path
        with pytest.raises(ValueError) as exc_info:
            validate_path("")
        assert "Path cannot be empty" in str(exc_info.value)
