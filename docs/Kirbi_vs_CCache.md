# kirbi2ccache — Architecture & File Format Reference

## Overview

`kirbi2ccache.py` is a zero-dependency Python script that converts Kerberos
credential files from **kirbi format** (Mimikatz/Rubeus) to **MIT ccache
format** (the standard credential cache used by MIT krb5, Java's
`sun.security.krb5`, and tools like `klist`).

```bash
python kirbi2ccache.py ticket.kirbi          # → ticket.ccache
python kirbi2ccache.py ticket.kirbi out.bin   # → out.bin
python kirbi2ccache.py base64.kirbi           # Rubeus base64 input
```

---

## Kirbi File Format

A kirbi file is a `DER-encoded` **KRB\_CRED** message (Kerberos protocol
message type 22), wrapped in an `[APPLICATION 22]` explicit tag.

### ASN.1 Structure (RFC 4120 §5.8)

```
KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    pvno            [0] INTEGER (5),
    msg-type        [1] INTEGER (22),
    tickets         [2] SEQUENCE OF Ticket,
    enc-part        [3] EncryptedData
}

EncryptedData ::= SEQUENCE {
    etype   [0] INTEGER (0),
    kvno    [1] INTEGER (OPTIONAL),
    cipher  [2] OCTET STRING
}
```

When `etype = 0` (no encryption — the usual case for exported kirbis), the
`cipher` field contains a DER-encoded **EncKrbCredPart**:

```
EncKrbCredPart ::= [APPLICATION 29] SEQUENCE {
    ticket-info  [0] SEQUENCE OF KrbCredInfo
}

KrbCredInfo ::= SEQUENCE {
    key         [0] EncryptionKey,
    prealm      [1] Realm (OPTIONAL),
    pname       [2] PrincipalName (OPTIONAL),
    flags       [3] TicketFlags (OPTIONAL),
    authtime    [4] KerberosTime (OPTIONAL),
    starttime   [5] KerberosTime (OPTIONAL),
    endtime     [6] KerberosTime (OPTIONAL),
    renew-till  [7] KerberosTime (OPTIONAL),
    srealm      [8] Realm (OPTIONAL),
    sname       [9] PrincipalName (OPTIONAL),
    caddr      [10] HostAddresses (OPTIONAL)
}
```

### Field Reference

| Tag | Field | Type | Description |
|-----|-------|------|-------------|
| `[0]` | key | `EncryptionKey` | Session key (keytype + keyvalue) |
| `[1]` | prealm | `Realm` (string) | Client realm |
| `[2]` | pname | `PrincipalName` | Client principal |
| `[3]` | flags | `TicketFlags` (bitmask) | Ticket flags |
| `[4]` | authtime | `KerberosTime` (GeneralizedTime) | Authentication time |
| `[5]` | starttime | `KerberosTime` | Start time (optional) |
| `[6]` | endtime | `KerberosTime` | End time |
| `[7]` | renew-till | `KerberosTime` | Renewable until |
| `[8]` | srealm | `Realm` (string) | Service realm |
| `[9]` | sname | `PrincipalName` | Service principal |

### Binary Kirbi vs Base64 (Rubeus)

Tools like Mimikatz write raw DER kirbis. Rubeus writes base64-encoded
kirbis. The script auto-detects: it tries binary DER first, and falls back
to base64 decode on parse failure.

---

## CCACHE File Format (MIT Credentials Cache v4)

Specification: part of MIT krb5 source (`cc_file.c`), implemented in Java's
`sun.security.krb5.internal.ccache.FileCredentialsCache`.

### Top-level Structure

```
[2 bytes]  file_format_version    always 0x0504 (== KRB5_FCC_FVNO_4)
[2 bytes]  header_len             total bytes of tagged header fields
[N bytes]  header_data            sequence of tag entries
[principal] primary_principal     default client principal
[credential] credential 0         first credential entry
[credential] credential 1         ...
...
```

All integer fields are **big-endian** (network byte order).

### Header Tag Section

```
header_len (2 bytes) → value 12 for a single delta-time tag
  ┌─ tag  (2 bytes) → 1 (FCC_TAG_DELTATIME)
  ├─ len  (2 bytes) → 8
  └─ data (8 bytes) → time_offset (4) + usec_offset (4)
```

The script writes a delta-time tag with both offsets set to 0.

### Principal Encoding

```
name_type (4 bytes)   e.g. 1 = KRB5_NT_PRINCIPAL
count     (4 bytes)   number of name components (NOT including realm)
realm     (4-byte length + UTF-8 bytes)
comp[0]   (4-byte length + UTF-8 bytes)
comp[1]   (4-byte length + UTF-8 bytes)
...
```

`count` = number of name-string components. The realm is written
separately before the components. Java's `readPrincipal` reconstructs by
reading `count + 1` strings (the first is the realm).

### Credential Entry

```
client      principal
server      principal
key         keyblock
times       4 × 4‑byte Unix timestamps (authtime, starttime, endtime, renew_till)
is_skey     1 byte  (0 = false)
flags       4 bytes ticket flags (native byte order, ×)
num_address 4 bytes (0)
num_auth    4 bytes (0)
ticket      4-byte length + raw DER Ticket
second_tkt  4-byte length + raw DER (empty for TGT/TGS)
```

#### Keyblock

```
keytype (2 bytes, signed big-endian)   e.g. 18 = AES256
etype   (2 bytes, signed big-endian)   always 0
keylen  (4 bytes big-endian)           length of keyvalue×
keyvalue (keylen bytes)
```

× Note: both minikerberos and this script write keylen as 2 bytes preceded
by 2 zero bytes (`struct.pack('>hhH', kt, 0, len(kv))`). Java's `readKey`
reads `readLength4()` = 4 bytes, so the combined `[0, 0, len_hi, len_lo]`
resolves to the correct key length. This is compatible as long as keys are
< 65536 bytes (always true for Kerberos).

#### Ticket Flags

The script writes flags in **little-endian** byte order to match
minikerberos's convention. Java reads flags as big-endian, so the bit
positions will be scrambled. This does not cause an `EOFException` but
flag semantics will be lost in Java. MIT krb5's `klist` shows correct
flags on little-endian hosts.

#### Times

Four consecutive Unix timestamps (`authtime`, `starttime`, `endtime`,
`renew_till`), each a big-endian unsigned 32-bit integer representing
seconds since 1970-01-01 UTC. Zero means "not set."

---

## Conversion Walkthrough

```
kirbi file                  ccache file
┌──────────────────┐        ┌──────────────────────┐
│  [APP 22] SEQUENCE│        │  version (0x0504)     │
│    pvno           │────┐   │  header               │
│    msg-type       │    │   │  primary_principal    │← client from krbcredinfo.pname
│    tickets[0]     │──┐ │   ├──────────────────────┤
│      Ticket DER   │←┼─┼─┐ │  client principal     │← krbcredinfo.pname + prealm
│    enc-part       │  │ │ │ │  server principal     │← krbcredinfo.sname + srealm
│      etype = 0    │  │ │ │ │  keyblock             │← krbcredinfo.key
│      cipher       │  │ │ │ │  times                │← krbcredinfo.authtime..renew-till
│        EncKrbCred │  │ │ │ │  is_skey = 0         │
│          ticket-  │  │ │ │ │  flags                │← krbcredinfo.flags
│          info[0]  │  │ │ │ │  num_address = 0     │
│            key    │──┘ │ │ │  num_authdata = 0    │
│            prealm │────┘ │ │  ticket               │← tickets[0] raw DER
│            pname  │──────┘ │  second_ticket (empty)│
│            flags  │────────┘ └──────────────────────┘
│            ...
└──────────────────┘
```

### Step-by-step in `kirbi_to_ccache()`

1. **`parse_der(data)`** — Recursive TLV parser walks the DER tree,
   recording absolute byte offsets (`start`, `end`) for every node.

2. **`parse_krbcred(data)`** — Navigates the KRBCRED structure:
   - Extracts raw `tickets[0]` DER bytes via `data[tkt.start:tkt.end]`
   - Decrypts (trivially, since etype=0) the `enc-part.cipher` field,
     then extracts `KrbCredInfo` fields.

3. **`parse_krbcredinfo(tlv)`** — Reads all 10 `[APPLICATION n]` fields
   of `KrbCredInfo` into a dict.

4. **CCACHE assembly** — Serializes the extracted data into the binary
   ccache layout using `struct.pack`.

### DER TLV Parser Details

The parser handles:
- **Universal tags**: INTEGER (0x02), BIT STRING (0x03), OCTET STRING
  (0x04), NULL (0x05), UTF8String (0x0C), IA5String/VisibleString/
  GeneralString (0x16/0x1A/0x1B), GeneralizedTime (0x18), SEQUENCE (0x30)
- **Constructed tags** (tag & 0x20): recursively parses children
- **Long-form lengths** (len_byte & 0x80): up to 127 length-octets

Key design decision: **recursion always uses the original `data` buffer
with absolute offsets**, never sliced copies. This ensures that TLVs store
correct absolute `start`/`end` positions relative to the kirbi file,
enabling exact byte extraction of the Ticket DER.

### Parsed KrbCredInfo Fields

```
info = {
    'key':        (keytype_int, keyvalue_bytes),
    'prealm':     str,
    'pname':      (name_type_int, [name_strings]),
    'flags':      int (bitmask from BIT STRING),
    'authtime':   int (Unix timestamp),
    'starttime':  int,
    'endtime':    int,
    'renew_till': int,
    'srealm':     str,
    'sname':      (name_type_int, [name_strings]),
}
```

---

## Compatibility Notes

| Reader | Version | Header Tag | Flags Byte Order | Ticket |
|--------|---------|------------|-----------------|--------|
| MIT `klist` (v1.12+) | 0x0504 | reads via `>= v4` check | native (LE on x86) | any valid DER |
| Java `FileCredentialsCache` | 0x0504 | reads via `== KRB5_FCC_FVNO_4` check | big-endian read | any valid DER |
| minikerberos (Python) | 0x0504 | reads via `>= 2 bytes` | little-endian write | any valid DER |

- **Version**: 0x0504 is correct for all readers. 0x0400 is rejected by MIT
  krb5 (`KRB5_CCACHE_BADVNO`).
- **Flags**: Written LE (matching minikerberos and MIT on LE hosts). Java
  reads BE, so flag values appear scrambled in Java — this is cosmetic and
  does not affect credential usage.
- **Keyblock**: The 2 zero-bytes + 2-byte-length encoding accidentally
  matches Java's `readLength4()` when etype = 0, which it always is.

---

## References

- RFC 4120 — The Kerberos Network Authentication Service (V5)
- MIT krb5 source: `src/lib/krb5/ccache/cc_file.c`
- OpenJDK: `sun/security/krb5/internal/ccache/`
  - `FileCredentialsCache.java`
  - `CCacheInputStream.java`
  - `FileCCacheConstants.java` (`KRB5_FCC_FVNO_4 = 0x504`)
- Mimikatz / Rubeus: kirbi = DER-encoded KRB-CRED
