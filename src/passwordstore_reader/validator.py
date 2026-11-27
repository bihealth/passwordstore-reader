import os
import re


class ValidPath(str):
    """A validated path that is safe to use in filesystem operations."""

    pass


def validate_path(path: str, password_store_dir: str | None = None) -> ValidPath:
    """Validate that a path is safe, doesn't contain malicious characters, and is within the
    store dir.

    Args:
        path: The path to validate
        password_store_dir: The root directory of the password store (optional, but recommended)

    Raises:
        ValueError: If the path contains unsafe characters or escapes the store dir
    """
    if not path:
        raise ValueError("Path cannot be empty")

    # Explicitly check for path traversal attempts first (security-critical)
    if ".." in path or "\\" in path:
        raise ValueError(f"Path traversal attempt detected: {path}")

    # Only allow alphanumeric characters, hyphens, underscores, dots, and slashes
    if not re.match(r"^[a-zA-Z0-9._/-]+$", path):
        raise ValueError(
            f"Invalid path: {path}. "
            "Only alphanumeric, hyphens, underscores, dots, and slashes allowed"
        )

    # Absolute path enforcement: ensure path is within password_store_dir if provided
    if password_store_dir is not None:
        real_path = os.path.realpath(path)
        real_store = os.path.realpath(password_store_dir)
        if not real_path.startswith(real_store + os.sep):
            raise ValueError(f"Resolved path escapes password store directory: {path}")

    # Check if the path points to an existing directory or file
    if not os.path.isdir(path) and not os.path.isfile(path):
        raise ValueError(f"Invalid path: {path}. Path does not point to a directory or file")

    return ValidPath(path)
