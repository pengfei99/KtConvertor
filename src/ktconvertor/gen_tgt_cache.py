from __future__ import annotations

import base64
import getpass
import os
import sys
from pathlib import Path
from typing import Any

from minikerberos.protocol.asn1_structs import EncKrbCredPart, KRB_CRED

from ktconvertor.get_tgt import get_tgt
from ktconvertor.kirbi2ccache import kirbi_to_ccache


def _print_ticket_info(raw_ticket: bytes) -> None:
    """
    Parse and print a summary of a raw Kerberos KRB_CRED (kirbi) ticket payload.

    Deserializes the ASN.1 BER/DER encoded `KRB_CRED` structure, extracts target SPNs,
    and displays decrypted session ticket metadata (client identity, lifetime timestamps,
    flags, and base64-encoded session key).
    :param raw_ticket: The raw BER-encoded `KRB_CRED` (kirbi) binary data.
    :return:
    """
    # 1. Parse raw BER bytes into Python dictionary structure
    credential: dict[str, Any] = KRB_CRED.load(raw_ticket).native

    # 2. Display outer ticket target details (SPN & Realm)
    for ticket in credential.get("tickets", []):
        realm = ticket.get("realm", b"").decode() if isinstance(ticket.get("realm"), bytes) else str(
            ticket.get("realm", ""))
        sname = ticket.get("sname", {})
        parts = [s.decode() if isinstance(s, bytes) else str(s) for s in sname.get("name-string", [])]
        print(f"  SPN:    {'/'.join(parts)}")
        print(f"  Realm:  {realm}")

    # 3. Display inner decrypted ticket metadata (when etype == 0)
    enc_part = credential.get("enc-part", {})

    if enc_part.get("etype") == 0:
        cipher_bytes: bytes = enc_part.get("cipher", b"")
        cred_part: dict[str, Any] = EncKrbCredPart.load(cipher_bytes).native

        for info in cred_part.get("ticket-info", []):
            key = info.get("key", {})
            key_type = key.get("keytype", "?")
            key_value = base64.b64encode(key.get("keyvalue", b"")).decode()
            flags = info.get("flags", [])
            print(f"  Client:   {'/'.join(info.get('pname', {}).get('name-string', []))}")
            print(f"  Realm:    {info.get('prealm', '')}")
            print(f"  Start:    {info.get('starttime', '?')}")
            print(f"  End:      {info.get('endtime', '?')}")
            print(f"  Renew:    {info.get('renew-till', '?')}")
            print(f"  Flags:    {', '.join(flags) if flags else '?'}")
            print(f"  KeyType:  {key_type}")
            print(f"  Key:      {key_value}")
    print(f"  KirbiB64: {base64.b64encode(raw_ticket).decode()}")


def gen_cache_path() -> Path:
    """
    Generate the Kerberos ccache path for Windows operating systems.
    Raises OSError: If executed on any non-Windows platform.
    :return: the default MIT Kerberos ccache path for Windows operating systems.
    """

    # 1. Early-Exit Guard Clause for Operating System
    if sys.platform != "win32":
        raise OSError("This tool only works for Windows OS.")

    # 2. Determine target username
    target_user = getpass.getuser()

    # 3. Resolve user profile directory via USERPROFILE with fallback
    profile_dir = os.environ.get("USERPROFILE")
    base_path = Path(profile_dir) if profile_dir else Path.home()

    # 4. Construct and normalize cache file path
    cache_path = base_path / f"krb5cc_{target_user}"

    return cache_path

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Extract current user's Kerberos TGT")
    ap.add_argument("--target", help="SPN (default: cifs\\<LOGONSERVER>)")
    ap.add_argument("-o", "--out-file", help="Save TGT as kirbi file")
    args = ap.parse_args()

    kirbi_raw = get_tgt(args.target)
    _print_ticket_info(kirbi_raw)

    try:
        mit_ccache = kirbi_to_ccache(kirbi_raw)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


    if args.out_file:
        out_path = args.out_file
    else:
        out_path = gen_cache_path()

    with open(out_path, "wb") as f:
        f.write(mit_ccache)
    print(f"[+] Wrote TGT ({len(mit_ccache)} bytes) to {out_path}")
    return


if __name__ == "__main__":
    main()