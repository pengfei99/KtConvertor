"""
Extract the current Windows user's Kerberos TGT via SSPI/LSA APIs.

Usage:
    python get_tgt.py
    python get_tgt.py --target cifs/dc.corp.local
    python get_tgt.py -o ticket.kirbi

Dependencies:
    pip install minikerberos asn1crypto
"""
# this tells Python to store type hints as unevaluated strings at definition time, completely solving forward reference issues.
from __future__ import annotations
import os
# Imports Python's pre-defined C-compatible Windows API types (such as DWORD, HANDLE, BOOL).
import ctypes.wintypes
import sys
# Structure: Base class for defining C-style struct memory layouts in Python.
# POINTER: Factory function to create pointer types (equivalent to T* in C).
# byref: Creates a lightweight pointer reference to pass ctypes objects to C functions efficiently without full pointer instantiation.
# pointer: Instantiates a full ctypes pointer object.
# cast: Casts raw ctypes pointers or memory addresses to different type pointers (like (void*) in C).
# addressof: Returns the memory address of a ctypes object as an integer.
# c_void_p, c_ushort, c_char, c_byte, c_ulong: C-compatible primitive data types representing void*, unsigned short, char, unsigned char/byte, and unsigned long.
# create_string_buffer: Allocates a mutable block of memory (a byte buffer).
# sizeof: Calculates the byte size of a ctypes data type or structure in memory.
# string_at: Reads a specified number of raw bytes from a target memory address.
# WinError: Converts Windows OS error codes into Python-native OSError exceptions.
from ctypes import (
    Structure, POINTER, byref, pointer, cast, addressof,
    c_void_p, c_ushort, c_char, c_byte,
    c_ulong, create_string_buffer, sizeof, string_at, WinError,
)
# HANDLE, LONG: Windows-specific type abstractions for system handles (void*) and signed 32-bit integers (long).
from ctypes.wintypes import HANDLE, LONG
from enum import IntEnum
from typing import TypedDict, Tuple

from asn1crypto import core
from minikerberos.protocol.asn1_structs import AP_REQ, KRB_CRED, EncryptedData, Authenticator
from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.protocol.structures import AuthenticatorChecksum, ChecksumFlags

from ktconvertor.kirbi2ccache import kirbi_to_ccache

# Platform Guard: Ensure ctypes Windows definitions fail fast on non-Windows environments
if sys.platform != "win32":
    raise ImportError("This tool is designed for Windows only.")
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
#  These lines establish C-style naming conventions mirroring standard Windows SDK headers
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


# ============================================================
#  LSA structures
# ============================================================

class LUID(Structure):
    """
    Defines a standard Windows Locally Unique Identifier structure.
    """
    _fields_ = [
        ("LowPart", ULONG),
        ("HighPart", LONG)
    ]

    def to_int(self) -> int:
        """Combine HighPart and LowPart into a single 64-bit integer."""
        return (self.HighPart << 32) + self.LowPart

    @staticmethod
    def from_int(i: int) -> LUID:
        """
        Factory method to construct an LUID instance from a 64-bit integer.
        :param i:
        :return:
        """
        l = LUID()
        l.HighPart = i >> 32
        l.LowPart = i & 0xFFFFFFFF
        return l


# creates a module-level alias for a C pointer type that points to an LUID structure.
PLUID = POINTER(LUID)

# In the Windows SDK (ntdef.h), Microsoft defines LSA_STRING (and its alias STRING) to represent length-prefixed
# ANSI/ASCII byte buffers used by Local Security Authority (LSA) APIs:
"""
typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, *PSTRING, LSA_STRING, *PLSA_STRING;
"""


class LsaString(Structure):
    """
    It defines a C-compatible memory layout for the Windows LSA_STRING structure using Python's ctypes module
    Length:     USHORT (16-bit), The actual byte count of the data stored in Buffer (excluding any trailing null character).
    MaximumLength: USHORT (16-bit), The total memory allocated for Buffer in bytes.
    Buffer: POINTER(c_char), A pointer to a C character array (char*) holding the raw bytes in memory.
    """
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", POINTER(c_char))]


# creates a module-level alias for a C pointer type that points to a LsaString.
PLsaString = POINTER(LsaString)


class LsaUnicodeString(Structure):
    """
    Represents the native Windows LSA_UNICODE_STRING / UNICODE_STRING structure.

        In the Windows API, UNICODE_STRING manages length-prefixed UTF-16-LE strings.
        Crucially, both `Length` and `MaximumLength` are measured in **bytes**,
        not character counts.
    """
    _fields_ = [("Length", USHORT), ("MaximumLength", USHORT), ("Buffer", POINTER(c_char))]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Anchor underlying buffer memory to prevent Python's Garbage Collector
        # from freeing the C memory while Windows native APIs hold the pointer.
        self._keep_alive: ctypes.Array[c_char] | None = None

    @staticmethod
    def from_string(s: str):
        """
        Factory method to construct an LsaUnicodeString from a Python string.
        :param s: The Python string to convert into a UTF-16-LE byte buffer.
        :return: An instance of LsaUnicodeString containing a pointer to the UTF-16-LE encoded buffer.
        """
        # Encode string to UTF-16-LE (without byte order mark)
        enc = s.encode("utf-16-le")
        lus = LsaUnicodeString()
        buf = create_string_buffer(enc, len(enc))
        lus.Buffer = cast(buf, POINTER(c_char))
        lus.MaximumLength = len(enc) + 1
        lus.Length = len(enc)
        lus._keep_alive = buf
        return lus

    def to_string(self):
        """
        Decode the underlying UTF-16-LE C buffer into a native Python string.
        :return: The decoded string, or an empty string if the Buffer is NULL or Length is 0.
        """
        if not self.Buffer or self.Length == 0:
            return ""
        return string_at(self.Buffer, self.Length).decode("utf-16-le", errors="strict")


class KerbCryptoKeyDict(TypedDict):
    """Type definition for the dictionary representation of a KerbCryptoKey."""
    KeyType: int
    Key: bytes


class KerbCryptoKey(Structure):
    """
    Represents the native Windows KERB_CRYPTO_KEY structure (ntsecapi.h).

    Used by Local Security Authority (LSA) APIs to return cryptographic key material
    (such as Kerberos session keys) along with their encryption algorithm ID (etype).
    """
    _fields_ = [
        ("KeyType", LONG),
        ("Length", ULONG),
        ("Value", PVOID)
    ]

    @property
    def key_bytes(self) -> bytes:
        """
        Safely extract raw cryptographic key bytes from the Value pointer.
        :return: Raw binary key material, or b"" if Value is NULL or Length is 0.
        """
        # Guard against NULL pointer dereferences or zero-length allocations
        if not self.Value or self.Length == 0:
            return b""
        return string_at(self.Value, self.Length)

    def to_dict(self) -> KerbCryptoKeyDict:
        """
        Export key metadata and raw key material to a typed dictionary.
        :return: KerbCryptoKeyDict: A dictionary containing 'KeyType' (int) and 'Key' (bytes).
        """
        return {
            "KeyType": int(self.KeyType),
            "Key": self.key_bytes,
        }


class KerbExternalTicketDataDict(TypedDict):
    """Type definition for the dictionary payload returned by KerbExternalTicket.get_data()."""
    Key: KerbCryptoKeyDict
    Ticket: bytes


class KerbExternalTicket(Structure):
    """Represents the native Windows KERB_EXTERNAL_TICKET structure (ntsecapi.h).

        Used by Local Security Authority (LSA) authentication packages (e.g.,
        `KerbRetrieveEncodedTicketMessage`) to return an encoded Kerberos ticket
        along with its associated session key, timestamps, and target metadata.
    """
    _fields_ = [
        ("ServiceName", PVOID),
        ("TargetName", PVOID),
        ("ClientName", PVOID),
        ("DomainName", LsaUnicodeString),
        ("TargetDomainName", LsaUnicodeString),
        ("AltTargetDomainName", LsaUnicodeString),
        ("SessionKey", KerbCryptoKey),
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

    @property
    def ticket_bytes(self) -> bytes:
        """
        Safely extract raw encoded Kerberos ticket bytes from EncodedTicket.
        :return: Raw binary ticket data, or b"" if EncodedTicket is NULL or size is 0.
        """
        # Guard against NULL pointer dereferences or zero-size buffers
        if not self.EncodedTicket or self.EncodedTicketSize == 0:
            return b""
        return string_at(self.EncodedTicket, self.EncodedTicketSize)

    def get_data(self) -> KerbExternalTicketDataDict:
        """
        Extract the session key metadata dictionary and raw ticket bytes.
        :return: A typed dictionary containing 'Key' and 'Ticket'.
        """
        return {"Key": self.SessionKey.to_dict(), "Ticket": self.ticket_bytes}


class KerbRetrieveTktResponse(Structure):
    """Represents the native Windows KERB_RETRIEVE_TKT_RESPONSE structure (ntsecapi.h).

        This structure is returned in the output response buffer by `LsaCallAuthenticationPackage`
        when calling with `KerbRetrieveEncodedTicketMessage`. It wraps the retrieved external
        Kerberos ticket along with its session key and metadata.
    """
    _fields_ = [("Ticket", KerbExternalTicket)]

    @property
    def ticket_data(self) -> KerbExternalTicketDataDict:
        """
        Convenience property to extract session key metadata and raw ticket bytes.
        :return: A typed dictionary containing 'Key' and 'Ticket'.
        """
        return self.Ticket.get_data()


# ============================================================
#  SSPI structures
# In Windows SSPI (sspi.h), credentials and security contexts use identical memory structures under the hood.
# Microsoft defines them as typedef aliases of SecHandle
# typedef struct _SecHandle {
#     ULONG_PTR dwLower;
#     ULONG_PTR dwUpper;
# } SecHandle, *PSecHandle;

# typedef SecHandle CredHandle, *PCredHandle;
# typedef SecHandle CtxtHandle, *PCtxtHandle;
# ============================================================

class SecHandle(Structure):
    """Represents the native Windows SecHandle structure (sspi.h).

        In the Windows Security Support Provider Interface (SSPI), SecHandle is the
        foundational structure used to represent opaque security context and credential
        handles. It consists of two pointer-sized lower and upper integer values.
    """
    _fields_ = [
        ("dwLower", POINTER(ULONG)),
        ("dwUpper", POINTER(ULONG))
    ]

    def __init__(self):
        super().__init__(pointer(ULONG()), pointer(ULONG()))


# Credential Handle Aliases (used in AcquireCredentialsHandle)
CredHandle = SecHandle
PCredHandle = POINTER(CredHandle)
# Security Context Handle Aliases (used in InitializeSecurityContext / AcceptSecurityContext)
CtxtHandle = SecHandle
PCtxtHandle = POINTER(CtxtHandle)


class TimeStamp(Structure):
    """Represents the native Windows TimeStamp / FILETIME structure (sspi.h / minwinbase.h).

        Contains a 64-bit value representing the number of 100-nanosecond intervals
        elapsed since 12:00 A.M. January 1, 1601 (UTC).
    """
    _fields_ = [("dwLowDateTime", ULONG), ("dwHighDateTime", ULONG)]


# Module-level cached pointer type definition (sspi.h)
PTimeStamp = POINTER(TimeStamp)


class SecBufferType(IntEnum):
    """Standard SSPI Security Buffer Types (sspi.h)."""

    EMPTY = 0
    DATA = 1
    TOKEN = 2
    PKG_PARAMS = 3
    STREAM_HEADER = 6
    STREAM_TRAILER = 7


class SecBuffer(Structure):
    """Represents the native Windows SecBuffer structure (sspi.h).

        Used by Security Support Provider Interface (SSPI) functions to exchange
        security tokens, authentication descriptors, and decrypted payloads.
    """
    _fields_ = [("cbBuffer", ULONG), ("BufferType", ULONG), ("pvBuffer", PVOID)]

    def __init__(self, token: bytes | bytearray | int | None = None,
                 buffer_type: int | SecBufferType = SecBufferType.TOKEN):
        """
        Initialize a SecBuffer instance.
        :param token: Initial byte payload, integer capacity to pre-allocate, or None to allocate a default 2,880-byte buffer.
        :param buffer_type: SSPI buffer type flag (defaults to SECBUFFER_TOKEN = 2).
        """
        if token is None:
            # Default initial allocation size for SSPI security tokens
            token = b"\x00" * 2880
        # Allocate buffer and anchor reference on self to prevent Garbage Collection
        self._buf = create_string_buffer(token, len(token))

        super().__init__(sizeof(self._buf), buffer_type, cast(self._buf, PVOID))

    @property
    def raw_bytes(self) -> bytes:
        """
        Safely extract raw bytes from the pvBuffer memory location.
        :return: The raw byte payload, or b"" if pvBuffer is NULL or size is 0.
        """
        if not self.pvBuffer or self.cbBuffer == 0:
            return b""
        return string_at(self.pvBuffer, self.cbBuffer)

    @property
    def Buffer(self) -> Tuple[int, bytes]:
        return int(self.BufferType), self.raw_bytes

    def __repr__(self) -> str:
        """Return a developer-friendly representation of the buffer state."""
        try:
            type_name = SecBufferType(self.BufferType).name
        except ValueError:
            type_name = f"CUSTOM({self.BufferType})"
        return f"<{self.__class__.__name__} type={type_name} size={self.cbBuffer} bytes>"


SECBUFFER_VERSION = 0  # Standard SECBUFFER_VERSION constant from sspi.h


class SecBufferDesc(Structure):
    """Represents the native Windows SecBufferDesc structure (sspi.h).

        Serves as an array descriptor container for one or more SecBuffer structures,
        exchanged during SSPI authentication calls such as InitializeSecurityContext
        and AcceptSecurityContext.
    """
    _fields_ = [
        ("ulVersion", ULONG),
        ("cBuffers", ULONG),
        ("pBuffers", POINTER(SecBuffer))
    ]

    def __init__(self, sb=None):
        if sb is not None:
            # keep elements alive via a slice copy
            arr = (SecBuffer * len(sb))(*sb)
            self._buf = arr  # keep ref
            # 3. Initialize Base C Structure
            super().__init__(SECBUFFER_VERSION, len(sb), arr)
        else:
            self._buf = SecBuffer()
            super().__init__(SECBUFFER_VERSION, 1, pointer(self._buf))

    @property
    def Buffers(self):
        """Legacy compatibility property matching original C API naming."""
        return [self.pBuffers[i].Buffer for i in range(self.cBuffers)]

    def __repr__(self) -> str:
        """Return an informative string representation."""
        return f"<{self.__class__.__name__} version={self.ulVersion} count={self.cBuffers}>"

    def __len__(self) -> int:
        """Return the number of buffers in the descriptor."""
        return int(self.cBuffers)


# Module-level cached pointer type definition
PSecBufferDesc = POINTER(SecBufferDesc)

# ============================================================
#  WinAPI — LSA
# ============================================================

# dynamically loads Windows' native Secur32.dll system library into Python's process memory space.
#
# This line grants Python direct access to lower-level Windows Security APIs, such as the SSPI (Security Support Provider Interface)
# and LSA (Local Security Authority) functions.
_secur32 = ctypes.windll.Secur32


def _check_nt(result: int, _func: object, _args: object) -> int:
    """ctypes errcheck callback for NTSTATUS functions (0x80000000+ = Warning/Error)."""
    if result != 0:
        raise WinError(result)
    return result


def LsaConnectUntrusted() -> HANDLE:
    """Establish an untrusted connection to the LSA server."""
    f = _secur32.LsaConnectUntrusted
    f.argtypes = [PHANDLE]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    handle = HANDLE(-1)
    f(byref(handle))
    return handle


def LsaDeregisterLogonProcess(lsa_handle: HANDLE) -> None:
    """Disconnect and release an active LSA logon process connection handle."""
    f = _secur32.LsaDeregisterLogonProcess
    f.argtypes = [HANDLE]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    f(lsa_handle)


def LsaFreeReturnBuffer(pointer_address: PVOID) -> None:
    """Free a memory buffer allocated and returned by LSA calls."""
    f = _secur32.LsaFreeReturnBuffer
    f.argtypes = [PVOID]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    f(pointer_address)


def LsaLookupAuthenticationPackage(lsa_handle: HANDLE, package_name: str | bytes) -> int:
    """
    Lookup the package ID for a specified authentication package (e.g., 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0').
    :param lsa_handle: lsa handle
    :param package_name: package name
    :return:
    """
    f = _secur32.LsaLookupAuthenticationPackage
    f.argtypes = [HANDLE, PLsaString, PULONG]
    f.restype = NTSTATUS
    f.errcheck = _check_nt

    b = package_name.encode() if isinstance(package_name, str) else package_name
    s = LsaString()
    s.Buffer = create_string_buffer(b)
    s.Length = len(b)
    s.MaximumLength = len(b) + 1
    pid = ULONG(0)
    f(lsa_handle, byref(s), byref(pid))
    return pid.value


def LsaCallAuthenticationPackage(lsa_handle: HANDLE, pkg_id: int, msg: bytes | Structure | PVOID, ):
    """
    Returns (response_bytes, free_ptr, ret_status).
    Caller must LsaFreeReturnBuffer(free_ptr) once response parsing is done.
    """
    f = _secur32.LsaCallAuthenticationPackage
    f.argtypes = [HANDLE, ULONG, PVOID, ULONG, PPVOID, PULONG, PNTSTATUS]
    f.restype = ULONG
    f.errcheck = _check_nt

    msg_len = sizeof(msg) if isinstance(msg, Structure) else len(msg) if isinstance(msg, bytes) else 0

    ret_p = PVOID()
    ret_len = ULONG(0)
    ret_st = LONG(-1)
    f(lsa_handle, pkg_id, byref(msg), msg_len, byref(ret_p), byref(ret_len), byref(ret_st))

    if ret_st.value != 0:
        raise WinError(ret_st.value)

    if ret_len.value > 0:
        return string_at(ret_p, ret_len.value), ret_p, ret_st.value
    return b"", None, ret_st.value


# ============================================================
#  WinAPI — SSPI
# ============================================================

def _check_sec(result, func, args):
    if result in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        return result
    raise RuntimeError(f"SSPI call failed: {result:#x}")


def AcquireCredentialsHandle(pkg_name, cred_usage):
    f = _secur32.AcquireCredentialsHandleA
    f.argtypes = [POINTER(c_char), POINTER(c_char), ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp]
    f.restype = ULONG
    f.errcheck = _check_sec

    pn = create_string_buffer(pkg_name.encode("ascii"))
    creds = CredHandle()
    ts = TimeStamp()
    f(None, pn, cred_usage, None, None, None, None, byref(creds), byref(ts))
    return creds


def InitializeSecurityContext(creds, spn, flags, ctx_in=None, token=None):
    f = _secur32.InitializeSecurityContextA
    f.argtypes = [PCredHandle, PCtxtHandle, POINTER(c_char), ULONG, ULONG, ULONG,
                  PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp]
    f.restype = ULONG
    f.errcheck = _check_sec

    pspn = create_string_buffer(spn.encode("ascii"))
    outbuf = SecBufferDesc()
    outflags = ULONG()
    expiry = TimeStamp()
    ctx_out = CtxtHandle()

    if token is not None:
        inbuf = SecBufferDesc([SecBuffer(token)])
        inbuf_ptr = byref(inbuf)
    else:
        inbuf_ptr = None

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
            ("TargetName", LsaUnicodeString),
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

    # Point LsaUnicodeString.Buffer to the trailing name bytes
    struct_end = addressof(req) + sizeof(req)
    name_start = struct_end - target_alloc
    name_start_aligned = name_start - (name_start % sizeof(c_void_p))

    lsa_target = LsaUnicodeString()
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
    ret_msg, free_ptr, ret_status = LsaCallAuthenticationPackage(lsa_handle, pkg_id, msg)
    if ret_status != 0:
        raise WinError(ret_status)
    resp = KerbRetrieveTktResponse.from_buffer_copy(ret_msg)
    ticket_data = resp.Ticket.get_data()
    if free_ptr is not None:
        LsaFreeReturnBuffer(free_ptr)
    return ticket_data


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
#  Main
# ============================================================

def get_tgt(target=None) -> bytes:
    """
    Retrieve the Kerberos Ticket Granting Ticket (TGT) via SSPI credential delegation.

    Requests an AP-REQ token from SSPI with delegation enabled (`ISC_REQ_DELEGATE`),
    extracts the target session key via LSA, decrypts the GSS-API authenticator
    checksum payload, and returns the resulting `KRB_CRED` (kirbi) structure.
    :param target: Target Service Principal Name (SPN), e.g., 'cifs/dc01.domain.local'.
            If None, defaults to 'cifs/<LOGONSERVER>' using the system environment variable.
    :return: Raw BER-encoded `KRB_CRED` (kirbi) binary data.
    """

    # 1. Resolve target SPN
    # todo not validation on the logonserver, if user enters a bad server name, the program will crash
    if target is None:
        logon_server = os.environ.get("LOGONSERVER", "").lstrip("\\")
        if not logon_server:
            raise RuntimeError(
                "Target SPN not provided and environment variable 'LOGONSERVER' is not set."
            )
        target = f"cifs/{logon_server}"

    # 2. Retrieve Kerberos Authentication Package ID
    lsa_handle = LsaConnectUntrusted()
    try:
        pkg_id = LsaLookupAuthenticationPackage(lsa_handle, "kerberos")
    finally:
        LsaDeregisterLogonProcess(lsa_handle)

    # 3. Request AP-REQ via SSPI with delegation enabled
    creds = AcquireCredentialsHandle("kerberos", SECPKG_CRED_OUTBOUND)
    flags = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY
    res, ctx, bufs = InitializeSecurityContext(creds, target, flags)

    if res not in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        raise RuntimeError(f"InitializeSecurityContext failed with status code: {res:#x}")

    # Extract AP-REQ ASN.1 InitialContextToken byte payload
    raw_token: bytes = bufs[0][1]

    # 4. Extract target Kerberos session key via LSA
    lsa_handle_2 = LsaConnectUntrusted()
    try:
        raw_ticket = extract_ticket(lsa_handle_2, pkg_id, 0, target)
    finally:
        LsaDeregisterLogonProcess(lsa_handle_2)

    session_key_meta = raw_ticket["Key"]
    key = Key(session_key_meta["KeyType"], session_key_meta["Key"])

    # 5. Parse AP-REQ and decrypt Authenticator
    ict = InitialContextToken.load(raw_token)
    apreq = AP_REQ(ict.native["innerContextToken"]).native

    cipher = _enctype_table[apreq["authenticator"]["etype"]]
    # Key Usage 11 = KRB_KEY_USAGE_AP_REQ_AUTH (RFC 4120 §7.5.8)
    auth_plain = cipher.decrypt(key, 11, apreq["authenticator"]["cipher"])
    authenticator = Authenticator.load(auth_plain).native

    # 6. Validate GSS-API delegation checksum (0x8003)
    ck = authenticator["cksum"]
    if ck["cksumtype"] != 0x8003:
        raise RuntimeError(f"Unexpected checksum type: {ck['cksumtype']:#x} (expected 0x8003)")

    cdata = AuthenticatorChecksum.from_bytes(ck["checksum"])
    if ChecksumFlags.GSS_C_DELEG_FLAG not in cdata.flags:
        raise RuntimeError("GSS_C_DELEG_FLAG missing — SSPI failed to delegate TGT.")

    # 7. Decrypt KRB_CRED inner payload
    cred_native = KRB_CRED.load(cdata.delegation_data).native
    # Key Usage 14 = KRB_KEY_USAGE_KRB_CRED_PART (RFC 4120 §7.5.8)
    cred_plain = cipher.decrypt(key, 14, cred_native["enc-part"]["cipher"])

    cred_native["enc-part"] = EncryptedData({"etype": 0, "cipher": cred_plain})
    return KRB_CRED(cred_native).dump()
