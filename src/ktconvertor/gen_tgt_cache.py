import getpass
import os
import sys
from pathlib import Path
from typing import Optional


def gen_cache_path(user: Optional[str] = None) -> str:
    """
    Generate MIT Kerberos ccache file path following OS-specific standards.

    Refined to prioritize XDG specs on Linux and robust path handling on Windows.
    """
    if sys.platform == "darwin":
        # macOS typically uses API-based credential caches (KCM), not flat files.
        raise NotImplementedError("macOS uses CCAPI; file-based paths are non-standard.")

    if os.name == "nt":
        # Windows best practice: Use USERPROFILE or LOCALAPPDATA for caches
        user = user or getpass.getuser()
        base = Path(os.environ.get("USERPROFILE", f"C:/Users/{user}"))
        return (base / f"krb5cc_{user}").as_posix()

    # Linux / Unix / POSIX
    # 1. Check for XDG_RUNTIME_DIR (Modern Linux standard, e.g., /run/user/1000)
    # 2. Fallback to /tmp with UID
    uid = os.getuid()
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")

    if runtime_dir:
        base_path = Path(runtime_dir)
    else:
        base_path = Path("/tmp")

    return (base_path / f"krb5cc_{uid}").as_posix()

