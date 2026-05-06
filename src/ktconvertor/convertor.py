import base64
import getpass
import os
import sys
from pathlib import Path
from typing import Optional

from asn1crypto import core
from minikerberos.common.ccache import CCACHE, Credential, CCACHEPrincipal, Times, Keyblock, CCACHEOctetString
from minikerberos.common.kirbi import Kirbi
from minikerberos.protocol.asn1_structs import EncKrbCredPart, TicketFlags, Ticket


def from_kirbi(kirbi: Kirbi):
    krbcred = kirbi.kirbiobj.native
    c = Credential()
    enc_credinfo = EncKrbCredPart.load(krbcred['enc-part']['cipher']).native
    ticket_info = enc_credinfo['ticket-info'][0]

    c.client = CCACHEPrincipal.from_asn1(ticket_info['pname'], ticket_info['prealm'])
    # yaaaaay 4 additional weirdness!!!!
    # if sname name-string contains a realm as well htne impacket will crash miserably :(
    if len(ticket_info['sname']['name-string']) > 2 and ticket_info['sname']['name-string'][-1].upper() == ticket_info[
        'srealm'].upper():
        print('SNAME contains the realm as well, trimming it')
        t = ticket_info['sname']
        t['name-string'] = t['name-string'][:-1]
        c.server = CCACHEPrincipal.from_asn1(t, ticket_info['srealm'])
    else:
        c.server = CCACHEPrincipal.from_asn1(ticket_info['sname'], ticket_info['srealm'])

    c.time = Times.from_asn1(ticket_info)
    c.key = Keyblock.from_asn1(ticket_info['key'])
    c.is_skey = 0  # not sure!

    c.tktflags = TicketFlags(ticket_info['flags']).cast(core.IntegerBitString).native
    c.num_address = 0
    c.num_authdata = 0
    c.ticket = CCACHEOctetString.from_asn1(
        Ticket(krbcred['tickets'][0]).dump())  # kirbi only stores one ticket per file
    c.second_ticket = CCACHEOctetString.empty()

    return c


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


def convert_kirbi(src:str, dest:str=None)->str:
    """
     This function convert the kirbi format to MIT ccache format.
    :param src: The path of source .kirbi file which contains the tgt binary in base64 format
    :param dest: The path of converted MIT ccache file
    :return:
    """
    # 1. Standardize path handling using Pathlib
    # This handles ../, ./, absolute paths, and OS-specific separators ( \ vs / )
    src_path = Path(src).expanduser().resolve()

    if not src_path.exists():
        raise FileNotFoundError(f"Source kirbi file not found: {src_path}")

    # 2. Use context managers for safe File I/O
    # This ensures the file handle is closed even if decoding fails
    try:
        with src_path.open("rb") as f:
            kirbi_b64 = f.read()

        # 3. Decode Base64 to raw bytes
        kirbi_bytes = base64.b64decode(kirbi_b64)
    except Exception as e:
        raise ValueError(f"Failed to read or decode kirbi file: {e}")

    # 4. Process the credential cache
    cc = CCACHE.from_bytes(kirbi_bytes)

    # 5. Determine destination
    if dest:
        dest_path = Path(dest).expanduser().resolve()
    else:
        # Fallback to our logic from the previous gen_cache_path function
        dest_path = Path(gen_cache_path())

    # Ensure the parent directory for the destination exists
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # 6. Write ticket to the file path
    final_path = dest_path.as_posix()
    cc.to_file(final_path)

    return final_path
