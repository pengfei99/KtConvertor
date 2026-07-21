# Architecture & File Format Reference

To understand how to convert a Kerberos ticket from `Windows KIRBI format` to `MIT CCACHE format`, you need to 
understand how both operating systems store Kerberos credentials.

While both files store the exact same underlying `cryptographic elements(e.g. a ticket, a session key, and client/server identities)`,
they wrap them in completely different `data formats`:
- Windows KIRBI format uses nested, `binary-tagged ASN.1 DER` structures, 
- MIT CCACHE format uses a `rigid, flat binary format built from big-endian length-prefixed fields`.


## 1. The Windows KIRBI Format (KRB-CRED)

A `.kirbi` file is not a custom proprietary Windows binary format; it is a raw `RFC 4120 KRB-CRED (Kerberos Credential) ASN.1 DER structure`. 
Security tools like `Rubeus` or `Mimikatz` export kerberos tickets in this format.

Because it uses ASN.1 DER (Distinguished Encoding Rules), data is structured as a `tree of TLV (Tag-Length-Value) blocks`.

### 1.1 Internal ASN.1 Structure (RFC 4120 §5.8) of KIRBI

When you expand a .kirbi file, it looks like this nested tree:

``` text
[APPLICATION 22] (KRB-CRED Outer Envelope)
└── SEQUENCE
    ├── [0] pvno INTEGER (5)
    ├── [1] msg-type INTEGER (22)
    ├── [2] tickets SEQUENCE OF
    │   └── Ticket [APPLICATION 1]  <-- The raw ticket passed to services!
    │       ├── tkt-vno INTEGER (5)
    │       ├── realm GeneralString
    │       ├── sname PrincipalName
    │       └── enc-part EncryptedData
    └── [3] enc-part EncryptedData
        └── EncKrbCredPart (Decrypted in Kirbi exports)
            └── ticket-info SEQUENCE OF
                └── KrbCredInfo
                    ├── [0] key EncryptionKey (kt: Int, kv: Bytes)
                    ├── [1] prealm GeneralString
                    ├── [2] pname PrincipalName
                    ├── [3] flags TicketFlags (BitString)
                    ├── [4] authtime GeneralizedTime
                    ├── [5] starttime GeneralizedTime
                    ├── [6] endtime GeneralizedTime
                    ├── [7] renew-till GeneralizedTime
                    ├── [8] srealm GeneralString
                    └── [9] sname PrincipalName
```

Key Elements of KIRBI:

- `tickets` Block [2]: Contains the actual opaque ticket (often encrypted with the service account's hash, e.g., krbtgt). The client does not read inside this block; it simply passes these exact raw bytes to the Kerberos service (like HDFS).

- `EncKrbCredPart / ticket-info` Block [3]: Contains the `session metadata` the client needs to use the ticket:

     - The Session Key (key): Used to sign/encrypt communication between the client and HDFS. 
     - The Client Identity (pname, prealm): Who owns this ticket. 
     - The Timestamps (authtime, starttime, endtime, renew_till): Expressed as ISO-like GeneralizedTime strings (e.g., "20260720080000Z").


### 1.2 `EncKrbCredPart / ticket-info` Block Field Reference

The `DER-encoded` field **EncKrbCredPart** only exists, When `etype = 0` (no encryption — the usual case for exported kirbis)

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

### 1.3 Kirbi in Binary vs Base64

Tools like `Mimikatz` exports and writes kirbi file in `raw DER(binary)`, which is hard to copy and past via text editers. 
As a result, tools like `Rubeus`, and `pypykatz` can export and write the kirbi file in `base64-encoded` plain-text file.


## 2. The MIT CCACHE Format (Version 4)

MIT Kerberos (used by Linux, macOS, Hadoop, HDFS, and kinit) stores credentials in a `flat, binary byte-stream file` 
known as CCACHE (typically `version 0x0504`). You can find the origin doc [here](https://web.mit.edu/KERBEROS/krb5-1.22/doc/basic/ccache_def.html)


The C implementation is in MIT krb5 source (`cc_file.c`), in Java `sun.security.krb5.internal.ccache.FileCredentialsCache`.

Unlike KIRBI's variable-length tagged structure, CCACHE relies on strict field positioning using `big-endian (>) multi-byte integers`.

### 2.1 Internal Binary Layout of CCACHE (v4)

A standard CCACHE file is composed of a Header, a Primary Principal, and one or more Credential Records:

```text
+-----------------------------------------------------------------------+
|                              FILE HEADER                              |
+-----------------------------------------------------------------------+
| Version (2 bytes)          | 0x0504 (KRB5_FCC_FVNO_4)                 |
| Header Length (2 bytes)    | Size of header extension block            |
| Header Tag & Data          | Optional context tags (e.g., KDC offsets) |
+-----------------------------------------------------------------------+
|                           PRIMARY PRINCIPAL                           |
+-----------------------------------------------------------------------+
| Name Type (4 bytes)        | e.g., 1 (KRB5_NT_PRINCIPAL)              |
| Component Count (4 bytes)  | Number of sub-strings (e.g., 1 for "user")|
| Realm Length + String      | 4-byte length + UTF-8 string              |
| Component 1 Length + String| 4-byte length + UTF-8 string              |
+-----------------------------------------------------------------------+
|                          CREDENTIAL RECORD 1                          |
+-----------------------------------------------------------------------+
| Client Principal           | (Same Principal format as above)         |
| Server Principal           | (Same Principal format as above)         |
| Keyblock                   | Type (2B), AuthType (2B), Len (2B), Key  |
| Times                      | authtime (4B), start (4B), end (4B), renew|
| Is-Server-Key Flag         | 1 byte (0x00)                            |
| Ticket Flags               | 4 bytes (Little-Endian integer!)          |
| Addresses                  | Count (4B) + Address list                |
| AuthData                   | Count (4B) + AuthData list               |
| Ticket Length + Data       | 4-byte length + Raw Ticket Bytes         |
| Second Ticket Length + Data| 4-byte length + Optional raw bytes        |
+-----------------------------------------------------------------------+
```

### 2.2 FILE Header Section

```
header_len (2 bytes) → value 12 for a single delta-time tag
  ┌─ tag  (2 bytes) → 1 (FCC_TAG_DELTATIME)
  ├─ len  (2 bytes) → 8
  └─ data (8 bytes) → time_offset (4) + usec_offset (4)
```

The script writes a delta-time tag with both offsets set to 0.

### 2.3 PRIMARY PRINCIPAL Section


- `Name Type (4 bytes)`:   e.g. 1 = KRB5_NT_PRINCIPAL 
- `Component Count (4 bytes)`:   number of name components (NOT including realm)
- `Realm (4-byte length + UTF-8 bytes)`: Realm of the KDC
- `comp[0]   (4-byte length + UTF-8 bytes)`
- `comp[1]   (4-byte length + UTF-8 bytes)`
- ETC.

> `Component Count` = number of name-string components. The realm is written separately before the components. 
> Java's `readPrincipal` reconstructs by reading `count + 1` strings (the first is the realm).

### 2.4 Credential Entry

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

#### 2.4.1 Keyblock

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

#### 2.4.2 Ticket Flags

The script writes flags in **little-endian** byte order to match
minikerberos's convention. Java reads flags as big-endian, so the bit
positions will be scrambled. This does not cause an `EOFException` but
flag semantics will be lost in Java. MIT krb5's `klist` shows correct
flags on little-endian hosts.

#### 2.4.3 Times

Four consecutive Unix timestamps (`authtime`, `starttime`, `endtime`,
`renew_till`), each a big-endian unsigned 32-bit integer representing
seconds since 1970-01-01 UTC. Zero means "not set."

---

## Conversion Walkthrough

The below figure shows the field correspondance between kirbi and CCache file.

```text
kirbi file                  ccache file
┌───────────────────┐        ┌───────────────────────┐
│  [APP 22] SEQUENCE│        │  version (0x0504)     │
│    pvno           │────┐   │  header               │
│    msg-type       │    │   │  primary_principal    │← client from krbcredinfo.pname
│    tickets[0]     │──┐ │   ├───────────────────────┤
│      Ticket DER   │ ←┼─┼─┐ │  client principal     │← krbcredinfo.pname + prealm
│    enc-part       │  │ │ │ │  server principal     │← krbcredinfo.sname + srealm
│      etype = 0    │  │ │ │ │  keyblock             │← krbcredinfo.key
│      cipher       │  │ │ │ │  times                │← krbcredinfo.authtime..renew-till
│        EncKrbCred │  │ │ │ │  is_skey = 0          │
│          ticket-  │  │ │ │ │  flags                │← krbcredinfo.flags
│          info[0]  │  │ │ │ │  num_address = 0      │
│            key    │──┘ │ │ │  num_authdata = 0     │
│            prealm │────┘ │ │  ticket               │← tickets[0] raw DER
│            pname  │──────┘ │  second_ticket (empty)│
│            flags  │────────┘ └─────────────────────┘
│            ...
└───────────────────┘
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