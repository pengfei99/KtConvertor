import os
import sys
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


from krbconvertor.convertor import gen_cache_path


class TestGenCachePath:

    @patch("sys.platform", "darwin")
    def test_macos_raises_error(self):
        """Ensure macOS triggers the expected NotImplementedError."""
        with pytest.raises(NotImplementedError, match="macOS uses CCAPI"):
            gen_cache_path()

    @patch("os.name", "nt")
    @patch("getpass.getuser", return_value="alice")
    @patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\alice"})
    def test_windows_path_generation(self, mock_getuser):
        """Verify Windows path logic using environment variables."""
        path = gen_cache_path()
        # Pathlib handles the slash conversion, .as_posix() ensures forward slashes
        assert path == "C:/Users/alice/krb5cc_alice"


    @patch("os.name", "nt")
    @patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\bob"})
    def test_explicit_user_override(self):
        """Ensure providing a 'user' argument overrides the system user."""
        path = gen_cache_path(user="admin")
        assert path == "C:/Users/bob/krb5cc_admin"

####### The linux os test will fail if you run under windows ###############
# the os module is dynamic; attributes like getuid or setuid simply do not exist when Python runs on Windows.
    @patch("os.name", "posix")
    @patch("sys.platform", "linux")
    @patch("os.getuid", return_value=1000)
    @patch.dict(os.environ, {}, clear=True)
    def test_linux_fallback_path(self, mock_uid):
        """Verify fallback to /tmp when XDG_RUNTIME_DIR is missing.
        """
        path = gen_cache_path()
        assert path == "/tmp/krb5cc_1000"

    @patch("os.name", "posix")
    @patch("sys.platform", "linux")
    @patch("os.getuid", return_value=1000)
    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"})
    def test_linux_xdg_path(self, mock_uid):
        """Verify preference for XDG_RUNTIME_DIR on modern Linux systems."""
        path = gen_cache_path()
        assert path == "/run/user/1000/krb5cc_1000"