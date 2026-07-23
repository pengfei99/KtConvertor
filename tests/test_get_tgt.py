"""Tests for get_tgt.py — Windows TGT extraction via SSPI/LSA (mocked)."""
import ctypes
import os
import pathlib
import sys
from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "src/ktconvertor" / "get_tgt.py"


def _ensure_ctypes_win():
    """Inject Windows-only ``ctypes`` names that don't exist on Linux."""
    if not hasattr(ctypes, 'WinError'):
        ctypes.WinError = lambda code=None: OSError(code)


@pytest.fixture(scope='module')
def gt():
    """Load get_tgt module with Windows-only deps mocked.

    Returns the module object so tests can access its functions and
    structures.  All Windows API calls (``ctypes.windll.Secur32.*``)
    are replaced with MagicMock, and ``sys.platform`` is forced to
    ``'win32'`` so the import guard passes.
    """
    _ensure_ctypes_win()
    mock_windll = MagicMock()

    with patch('sys.platform', 'win32'), \
         patch('ctypes.windll', mock_windll, create=True):
        import importlib.util
        spec = importlib.util.spec_from_file_location('get_tgt', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


# ── LUID ────────────────────────────────────────────────────────────

class TestLUID:
    def test_to_int(self, gt):
        luid = gt.LUID()
        luid.LowPart = 0xDEADBEEF
        luid.HighPart = 0xCAFE
        assert luid.to_int() == (0xCAFE << 32) | 0xDEADBEEF

    def test_from_int_zero(self, gt):
        luid = gt.LUID.from_int(0)
        assert luid.LowPart == 0
        assert luid.HighPart == 0

    def test_from_int_full_64bit(self, gt):
        val = (0x12345678 << 32) | 0x9ABCDEF0
        luid = gt.LUID.from_int(val)
        assert luid.LowPart == 0x9ABCDEF0
        assert luid.HighPart == 0x12345678

    def test_from_int_then_to_int_roundtrip(self, gt):
        for v in [0, 1, 0xFFFFFFFF, (1 << 63) - 1, (1 << 32), (1 << 33)]:
            assert gt.LUID.from_int(v).to_int() == v


# ── LsaUnicodeString ────────────────────────────────────────────────

class TestLsaUnicodeString:
    def test_from_string_roundtrip(self, gt):
        s = 'TEST.CORP'
        lus = gt.LsaUnicodeString.from_string(s)
        assert lus.to_string() == s

    def test_from_string_unicode(self, gt):
        s = 'Café☃'
        lus = gt.LsaUnicodeString.from_string(s)
        assert lus.to_string() == s

    def test_from_string_length_fields(self, gt):
        s = 'hello'
        enc = s.encode('utf-16-le')
        lus = gt.LsaUnicodeString.from_string(s)
        assert lus.Length == len(enc)
        assert lus.MaximumLength == len(enc) + 2

    def test_empty_string(self, gt):
        lus = gt.LsaUnicodeString.from_string('')
        assert lus.Length == 0
        assert lus.to_string() == ''


# ── KerbCryptoKey ───────────────────────────────────────────────────

class TestKerbCryptoKey:
    def test_key_bytes(self, gt):
        key = gt.KerbCryptoKey()
        raw = b'\x01\x02\x03\x04'
        buf = ctypes.create_string_buffer(raw, len(raw))
        key.KeyType = 18
        key.Length = len(raw)
        key.Value = ctypes.cast(buf, ctypes.c_void_p)
        assert key.key_bytes == raw

    def test_key_bytes_null_value(self, gt):
        key = gt.KerbCryptoKey()
        key.KeyType = 0
        key.Length = 10
        key.Value = None
        assert key.key_bytes == b''

    def test_key_bytes_zero_length(self, gt):
        key = gt.KerbCryptoKey()
        buf = ctypes.create_string_buffer(b'\x01\x02', 2)
        key.KeyType = 18
        key.Length = 0
        key.Value = ctypes.cast(buf, ctypes.c_void_p)
        assert key.key_bytes == b''

    def test_to_dict(self, gt):
        key = gt.KerbCryptoKey()
        raw = b'\xff' * 32
        buf = ctypes.create_string_buffer(raw, len(raw))
        key.KeyType = 18
        key.Length = len(raw)
        key.Value = ctypes.cast(buf, ctypes.c_void_p)
        d = key.to_dict()
        assert d == {'KeyType': 18, 'Key': raw}


# ── KerbExternalTicket ─────────────────────────────────────────────

class TestKerbExternalTicket:
    def test_ticket_bytes_zero_size(self, gt):
        tkt = gt.KerbExternalTicket()
        tkt.EncodedTicketSize = 0
        assert tkt.ticket_bytes == b''

    def test_ticket_bytes_null_ptr(self, gt):
        tkt = gt.KerbExternalTicket()
        tkt.EncodedTicketSize = 100
        tkt.EncodedTicket = None
        assert tkt.ticket_bytes == b''

    def test_ticket_bytes_returns_data(self, gt):
        tkt = gt.KerbExternalTicket()
        raw = b'\x7e' * 64
        buf = ctypes.create_string_buffer(raw, len(raw))
        tkt.EncodedTicketSize = len(raw)
        tkt.EncodedTicket = ctypes.cast(buf, ctypes.c_void_p)
        assert tkt.ticket_bytes == raw

    def test_get_data(self, gt):
        tkt = gt.KerbExternalTicket()
        raw = b'\x7e' * 64
        buf = ctypes.create_string_buffer(raw, len(raw))
        tkt.EncodedTicketSize = len(raw)
        tkt.EncodedTicket = ctypes.cast(buf, ctypes.c_void_p)
        # Also need a valid session key
        key_buf = ctypes.create_string_buffer(b'\x01' * 16, 16)
        tkt.SessionKey.KeyType = 23
        tkt.SessionKey.Length = 16
        tkt.SessionKey.Value = ctypes.cast(key_buf, ctypes.c_void_p)
        d = tkt.get_data()
        assert d['Key']['KeyType'] == 23
        assert d['Key']['Key'] == b'\x01' * 16
        assert d['Ticket'] == raw


class TestKerbRetrieveTktResponse:
    def test_ticket_data_property(self, gt):
        resp = gt.KerbRetrieveTktResponse()
        raw = b'\x7e' * 64
        buf = ctypes.create_string_buffer(raw, len(raw))
        resp.Ticket.EncodedTicketSize = len(raw)
        resp.Ticket.EncodedTicket = ctypes.cast(buf, ctypes.c_void_p)
        key_buf = ctypes.create_string_buffer(b'\x02' * 32, 32)
        resp.Ticket.SessionKey.KeyType = 18
        resp.Ticket.SessionKey.Length = 32
        resp.Ticket.SessionKey.Value = ctypes.cast(key_buf, ctypes.c_void_p)
        d = resp.ticket_data
        assert d['Key']['KeyType'] == 18
        assert d['Ticket'] == raw


# ── Errcheck callbacks ──────────────────────────────────────────────

class TestCheckFunctions:
    def test_check_nt_ok(self, gt):
        assert gt._check_nt(0, None, None) == 0

    def test_check_nt_error(self, gt):
        with pytest.raises(OSError):
            gt._check_nt(1, None, None)

    def test_check_sec_ok(self, gt):
        assert gt._check_sec(gt.SEC_E_OK, None, None) == gt.SEC_E_OK

    def test_check_sec_continue(self, gt):
        assert gt._check_sec(gt.SEC_E_CONTINUE_NEEDED, None, None) == gt.SEC_E_CONTINUE_NEEDED

    def test_check_sec_error(self, gt):
        with pytest.raises(RuntimeError, match='SSPI call failed'):
            gt._check_sec(0x80090300, None, None)


# ── _build_retrieve_request ─────────────────────────────────────────

class TestBuildRetrieveRequest:
    def test_message_type(self, gt):
        req = gt._build_retrieve_request('cifs/dc')
        assert req.MessageType == 8  # KerbRetrieveEncodedTicketMessage

    def test_target_name_roundtrip(self, gt):
        target = 'cifs/dc.domain.local'
        req = gt._build_retrieve_request(target)
        reconstructed = req.TargetName.to_string()
        assert reconstructed == target

    def test_target_name_length(self, gt):
        target = 'cifs/dc'
        enc = target.encode('utf-16-le')
        req = gt._build_retrieve_request(target)
        assert req.TargetName.Length == len(enc)
        assert req.TargetName.MaximumLength == len(enc) + 2

    def test_ticket_flags_zero(self, gt):
        req = gt._build_retrieve_request('cifs/dc')
        assert req.TicketFlags == 0

    def test_cache_options(self, gt):
        req = gt._build_retrieve_request('cifs/dc')
        assert req.CacheOptions == 8

    def test_encryption_type_zero(self, gt):
        req = gt._build_retrieve_request('cifs/dc')
        assert req.EncryptionType == 0

    def test_accepts_luid_object(self, gt):
        luid = gt.LUID.from_int(999)
        req = gt._build_retrieve_request('cifs/dc', luid=luid)
        assert req.LogonId.to_int() == 999

    def test_accepts_int_luid(self, gt):
        req = gt._build_retrieve_request('cifs/dc', luid=42)
        assert req.LogonId.to_int() == 42

    def test_unicode_in_target(self, gt):
        target = 'cifs/dc-é'
        req = gt._build_retrieve_request(target)
        reconstructed = req.TargetName.to_string()
        assert reconstructed == target


# ── extract_ticket ──────────────────────────────────────────────────

class TestExtractTicket:
    def test_calls_lsa_and_returns_ticket_data(self, gt):
        """extract_ticket calls LsaCallAuthenticationPackage and returns ticket data."""
        target = 'cifs/dc'
        raw_ticket = b'\x7e' * 128

        buf = ctypes.create_string_buffer(raw_ticket, len(raw_ticket))

        # Build a real KerbRetrieveTktResponse that from_buffer_copy can parse
        resp = gt.KerbRetrieveTktResponse()
        resp.Ticket.EncodedTicketSize = len(raw_ticket)
        resp.Ticket.EncodedTicket = ctypes.cast(buf, ctypes.c_void_p)
        resp_bytes = bytes(resp)

        # Patch LsaCallAuthenticationPackage to return our buffer
        gt.LsaCallAuthenticationPackage = MagicMock(
            return_value=(resp_bytes, ctypes.c_void_p(1), 0)
        )
        gt.LsaFreeReturnBuffer = MagicMock()

        result = gt.extract_ticket(0xDEAD, 0xBEEF, 0, target)

        assert 'Key' in result
        assert 'Ticket' in result

    def test_extract_ticket_raises_on_lsa_error(self, gt):
        """When LsaCallAuthenticationPackage returns non-zero status, raises OSError."""
        gt.LsaCallAuthenticationPackage = MagicMock(
            return_value=(b'', None, 1)
        )
        with pytest.raises(OSError):
            gt.extract_ticket(0, 0, 0, 'cifs/dc')


# ── get_tgt ─────────────────────────────────────────────────────────

class TestGetTgtTargetResolution:
    @patch.dict(os.environ, {'LOGONSERVER': '\\\\DC01'}, clear=True)
    def test_default_target_from_logonserver(self, gt):
        """When target is None, target becomes 'cifs/<LOGONSERVER>'."""
        with patch.object(gt, 'LsaConnectUntrusted') as mock_lcu, \
             patch.object(gt, 'LsaLookupAuthenticationPackage') as mock_llap, \
             patch.object(gt, 'LsaDeregisterLogonProcess') as mock_ldlp, \
             patch.object(gt, 'AcquireCredentialsHandle') as mock_ach, \
             patch.object(gt, 'InitializeSecurityContext') as mock_isc, \
             patch.object(gt, 'extract_ticket') as mock_et, \
             patch.object(gt, 'Key') as mock_key, \
             patch.object(gt, '_enctype_table', {}) as mock_etab, \
             patch.object(gt, 'InitialContextToken') as mock_ict, \
             patch.object(gt, 'AP_REQ') as mock_apreq, \
             patch.object(gt, 'KRB_CRED') as mock_krbcred, \
             patch.object(gt, 'EncryptedData') as mock_encdata, \
             patch.object(gt, 'Authenticator') as mock_auth, \
             patch.object(gt, 'AuthenticatorChecksum') as mock_checksum, \
             patch.object(gt, 'ChecksumFlags'):

            mock_lcu.side_effect = [0xAAA, 0xBBB]
            mock_llap.return_value = 999
            mock_ldlp.return_value = None
            mock_ach.return_value = 'creds_handle'
            mock_isc.return_value = (gt.SEC_E_OK, 'ctx', [(gt.SecBufferType.TOKEN, b'\x00' * 100)])
            mock_et.return_value = {'Key': {'KeyType': 18, 'Key': b'\x00' * 32}, 'Ticket': b'\x00' * 100}
            mock_key.return_value = 'key_obj'
            # populate _enctype_table
            enc_mock = MagicMock()
            enc_mock.decrypt.return_value = b'\x00' * 200
            gt._enctype_table = {0: enc_mock}
            mock_ict.load.return_value = MagicMock()
            mock_ict.load.return_value.native = {'innerContextToken': b''}
            mock_apreq.return_value.native = {
                'authenticator': {'etype': 0, 'cipher': b'\x00' * 100}
            }
            mock_auth.load.return_value.native = {
                'cksum': {'cksumtype': 0x8003, 'checksum': b'\x00' * 50}
            }
            mock_checksum.from_bytes.return_value.flags = [999]
            gt.ChecksumFlags.GSS_C_DELEG_FLAG = 999
            mock_krbcred.load.return_value.native = {
                'enc-part': {'cipher': b'\x00' * 200}
            }
            mock_encdata.return_value = 'encdata_obj'
            mock_krbcred.return_value.dump.return_value = b'\x7e\x81\x03'  # final kirbi output

            result = gt.get_tgt()

            assert result == b'\x7e\x81\x03'
            # Verify target was resolved from LOGONSERVER
            call_args = mock_isc.call_args[0]
            assert call_args[1] == 'cifs/DC01'

    def test_no_logonserver_raises(self, gt):
        """When target is None and LOGONSERVER is unset, get_tgt raises RuntimeError."""
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(gt, 'LsaConnectUntrusted') as mock_lcu, \
             patch.object(gt, 'LsaDeregisterLogonProcess'):

            mock_lcu.return_value = 0
            with pytest.raises(RuntimeError, match='LOGONSERVER'):
                gt.get_tgt()

    @patch.dict(os.environ, {'LOGONSERVER': '\\\\DC01'}, clear=True)
    def test_initialize_security_context_failure_raises(self, gt):
        """When InitializeSecurityContext returns an error status, get_tgt raises."""
        with patch.object(gt, 'LsaConnectUntrusted') as mock_lcu, \
             patch.object(gt, 'LsaDeregisterLogonProcess'), \
             patch.object(gt, 'LsaLookupAuthenticationPackage'), \
             patch.object(gt, 'AcquireCredentialsHandle'), \
             patch.object(gt, 'InitializeSecurityContext') as mock_isc:

            mock_lcu.return_value = 0
            mock_isc.return_value = (0x80090300, None, [])

            with pytest.raises(RuntimeError, match='InitializeSecurityContext failed'):
                gt.get_tgt()

    @patch.dict(os.environ, {'LOGONSERVER': '\\\\DC01'}, clear=True)
    def test_unexpected_checksum_type_raises(self, gt):
        """When the checksum type is not 0x8003, get_tgt raises RuntimeError."""
        with patch.object(gt, 'LsaConnectUntrusted') as mock_lcu, \
             patch.object(gt, 'LsaDeregisterLogonProcess'), \
             patch.object(gt, 'LsaLookupAuthenticationPackage'), \
             patch.object(gt, 'AcquireCredentialsHandle'), \
             patch.object(gt, 'InitializeSecurityContext') as mock_isc, \
             patch.object(gt, 'extract_ticket') as mock_et, \
             patch.object(gt, 'Key'), \
             patch.object(gt, '_enctype_table', {}), \
             patch.object(gt, 'InitialContextToken'), \
             patch.object(gt, 'AP_REQ'), \
             patch.object(gt, 'Authenticator'), \
             patch.object(gt, 'AuthenticatorChecksum'), \
             patch.object(gt, 'ChecksumFlags'):

            mock_lcu.return_value = 0
            mock_isc.return_value = (gt.SEC_E_OK, 'ctx', [(gt.SecBufferType.TOKEN, b'\x00' * 100)])
            mock_et.return_value = {'Key': {'KeyType': 18, 'Key': b'\x00' * 32}, 'Ticket': b'\x00'}
            enc_mock = MagicMock()
            enc_mock.decrypt.return_value = b'\x00' * 200
            gt._enctype_table = {0: enc_mock}
            gt.InitialContextToken.load.return_value.native = {'innerContextToken': b''}
            gt.AP_REQ.return_value.native = {
                'authenticator': {'etype': 0, 'cipher': b''}
            }
            gt.Authenticator.load.return_value.native = {
                'cksum': {'cksumtype': 0xABCD, 'checksum': b''}
            }

            with pytest.raises(RuntimeError, match='Unexpected checksum type'):
                gt.get_tgt()

    @patch.dict(os.environ, {'LOGONSERVER': '\\\\DC01'}, clear=True)
    def test_missing_delegation_flag_raises(self, gt):
        """When GSS_C_DELEG_FLAG is not set, get_tgt raises RuntimeError."""
        with patch.object(gt, 'LsaConnectUntrusted') as mock_lcu, \
             patch.object(gt, 'LsaDeregisterLogonProcess'), \
             patch.object(gt, 'LsaLookupAuthenticationPackage'), \
             patch.object(gt, 'AcquireCredentialsHandle'), \
             patch.object(gt, 'InitializeSecurityContext') as mock_isc, \
             patch.object(gt, 'extract_ticket') as mock_et, \
             patch.object(gt, 'Key'), \
             patch.object(gt, '_enctype_table', {}), \
             patch.object(gt, 'InitialContextToken'), \
             patch.object(gt, 'AP_REQ'), \
             patch.object(gt, 'Authenticator'), \
             patch.object(gt, 'AuthenticatorChecksum'), \
             patch.object(gt, 'ChecksumFlags'):

            mock_lcu.return_value = 0
            mock_isc.return_value = (gt.SEC_E_OK, 'ctx', [(gt.SecBufferType.TOKEN, b'\x00' * 100)])
            mock_et.return_value = {'Key': {'KeyType': 18, 'Key': b'\x00' * 32}, 'Ticket': b'\x00'}
            enc_mock = MagicMock()
            enc_mock.decrypt.return_value = b'\x00' * 200
            gt._enctype_table = {0: enc_mock}
            gt.InitialContextToken.load.return_value.native = {'innerContextToken': b''}
            gt.AP_REQ.return_value.native = {
                'authenticator': {'etype': 0, 'cipher': b''}
            }
            gt.Authenticator.load.return_value.native = {
                'cksum': {'cksumtype': 0x8003, 'checksum': b''}
            }
            gt.AuthenticatorChecksum.from_bytes.return_value.flags = [1, 2]
            gt.ChecksumFlags.GSS_C_DELEG_FLAG = 999  # not in flags

            with pytest.raises(RuntimeError, match='GSS_C_DELEG_FLAG missing'):
                gt.get_tgt()