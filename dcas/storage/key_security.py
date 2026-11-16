"""Restrict filesystem access to DCAS secret-key files."""

import os
import stat
import subprocess


def secure_private_file(path: str) -> None:
    """Make an existing secret-key file readable only by its service account."""
    path = os.path.abspath(path)
    if os.name == "nt":
        _secure_windows_file(path)
        return

    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"Secret-key file permissions are too broad: {path}")


def secure_new_private_file(path: str, descriptor: int) -> None:
    """Protect an empty, newly created key file before writing its secret."""
    try:
        secure_private_file(path)
    except Exception:
        close_error = None
        try:
            os.close(descriptor)
        except OSError as cleanup_error:
            close_error = cleanup_error
        try:
            os.remove(path)
        except OSError as cleanup_error:
            raise PermissionError(
                f"Could not secure or remove the new secret-key file: {path}"
            ) from cleanup_error
        if close_error is not None:
            raise PermissionError(
                f"Could not close the new secret-key file descriptor: {path}"
            ) from close_error
        raise


def _secure_windows_file(path: str) -> None:
    identity = subprocess.run(
        ["whoami"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not identity:
        raise PermissionError("Could not identify the Windows account for key protection.")

    commands = (
        ["icacls", path, "/reset"],
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", f"{identity}:(F)", "*S-1-5-18:(F)"],
    )
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            raise PermissionError(
                f"Could not restrict secret-key file permissions for {path}: {message}"
            )
