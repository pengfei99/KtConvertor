"""
Standalone kirbi → ccache converter.
Zero dependencies beyond Python stdlib.

Usage:
  python kirbi2ccache.py ticket.kirbi            # writes ticket.ccache
  python kirbi2ccache.py ticket.kirbi out.ccache  # writes out.ccache
  python kirbi2ccache.py input.kirbi             # also handles base64 (Rubeus)
"""

import struct
import sys
import os
import datetime
import base64


# ── Minimal DER TLV parser ──────────────────────────────────────────

class TLV:
    __slots__ = ('tag', 'start', 'end', 'tag_class', 'constructed', 'tag_num', 'value')
    def __init__(self, tag, start, end, value):
        self.tag = tag
        self.start = start
        self.end = end
        self.tag_class = tag >> 6
        self.constructed = (tag >> 5) & 1
        self.tag_num = tag & 0x1F
        self.value = value

    def __repr__(self):
        return f'TLV(tag=0x{self.tag:02x} class={self.tag_class} constructed={self.constructed} num={self.tag_num} len={self.end-self.start})'


def parse_der(data, offset=0):
    start = offset
    tag = data[offset]
    offset += 1
    len_byte = data[offset]
    offset += 1

    if len_byte & 0x80:
        n = len_byte & 0x7F
        length = 0
        for _ in range(n):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = len_byte

    end = offset + length

    if tag == 0x02:  # INTEGER
        value = int.from_bytes(data[offset:end], 'big', signed=True)
    elif tag == 0x04:  # OCTET STRING
        value = data[offset:end]
    elif tag == 0x03:  # BIT STRING
        value = int.from_bytes(data[offset + 1:end].rstrip(b'\x00'), 'big')
    elif tag == 0x05:
        value = None
    elif tag == 0x0C:  # UTF8String
        value = data[offset:end].decode('utf-8', errors='replace')
    elif tag in (0x16, 0x1A, 0x1B):  # IA5String / VisibleString / GeneralString
        value = data[offset:end].decode('utf-8', errors='replace')
    elif tag == 0x18:  # GeneralizedTime
        value = data[offset:end].decode('ascii', errors='replace')
    elif tag == 0x30 or (tag & 0x20):  # SEQUENCE / SEQUENCE OF / Constructed context-specific
        value = []
        o = offset
        while o < end:
            child, o = parse_der(data, o)
            value.append(child)
    else:
        value = data[offset:end]

    return TLV(tag, start, end, value), end


# ── Navigators ──────────────────────────────────────────────────────

def find_tag(children, tag_num, tag_class=2):
    for c in children:
        if c.tag_num == tag_num and c.tag_class == tag_class:
            return c
    return None

def unwrap_seq(tlv):
    """Given a context/application tag wrapping a SEQUENCE, return the SEQUENCE."""
    if tlv.constructed and len(tlv.value) > 0:
        return tlv.value[0]
    return None

def unwrap_prim(tlv):
    """Given a context tag wrapping a primitive, return the inner TLV."""
    if tlv.constructed and len(tlv.value) > 0:
        return tlv.value[0]
    return None


# ── Parsers ─────────────────────────────────────────────────────────

def parse_principal(seq_tlv):
    """Return (name_type: int, name_string: list[str])"""
    nt = 0; ns = []
    for c in seq_tlv.value:
        if c.tag_num == 0 and c.tag_class == 2:
            nt = unwrap_prim(c).value
        elif c.tag_num == 1 and c.tag_class == 2:
            seq_of = unwrap_seq(c)
            if seq_of:
                for s in seq_of.value:
                    ns.append(s.value)
    return nt, ns


def parse_kerberostime(gt_str):
    if not gt_str:
        return 0
    s = gt_str.rstrip('Z')
    if '.' in s:
        s = s.split('.')[0]
    try:
        dt = datetime.datetime.strptime(s, '%Y%m%d%H%M%S')
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return 0


def parse_krbcredinfo(seq_tlv):
    info = {}
    for c in seq_tlv.value:
        if c.tag_num == 0 and c.tag_class == 2:  # key
            ks = unwrap_seq(c)  # EncryptionKey SEQUENCE
            if ks:
                kt = 0; kv = b''
                for kf in ks.value:
                    if kf.tag_num == 0 and kf.tag_class == 2:
                        kt = unwrap_prim(kf).value
                    elif kf.tag_num == 1 and kf.tag_class == 2:
                        kv = unwrap_prim(kf).value
                info['key'] = (kt, kv)
        elif c.tag_num == 1 and c.tag_class == 2:  # prealm
            info['prealm'] = unwrap_prim(c).value
        elif c.tag_num == 2 and c.tag_class == 2:  # pname
            info['pname'] = parse_principal(unwrap_seq(c))
        elif c.tag_num == 3 and c.tag_class == 2:  # flags
            info['flags'] = unwrap_prim(c).value
        elif c.tag_num == 4 and c.tag_class == 2:  # authtime
            info['authtime'] = parse_kerberostime(unwrap_prim(c).value)
        elif c.tag_num == 5 and c.tag_class == 2:  # starttime
            info['starttime'] = parse_kerberostime(unwrap_prim(c).value)
        elif c.tag_num == 6 and c.tag_class == 2:  # endtime
            info['endtime'] = parse_kerberostime(unwrap_prim(c).value)
        elif c.tag_num == 7 and c.tag_class == 2:  # renew_till
            info['renew_till'] = parse_kerberostime(unwrap_prim(c).value)
        elif c.tag_num == 8 and c.tag_class == 2:  # srealm
            info['srealm'] = unwrap_prim(c).value
        elif c.tag_num == 9 and c.tag_class == 2:  # sname
            info['sname'] = parse_principal(unwrap_seq(c))
    return info


def parse_krbcred(data):
    outer, _ = parse_der(data)
    seq = outer.value[0] if outer.constructed else outer

    tickets_raw = []
    infos = []

    for field in seq.value:
        if field.tag_num == 2 and field.tag_class == 2:  # tickets
            tickets_seq = unwrap_seq(field)
            if tickets_seq:
                for tkt in tickets_seq.value:
                    tickets_raw.append(data[tkt.start:tkt.end])
        elif field.tag_num == 3 and field.tag_class == 2:  # enc-part
            enc_seq = unwrap_seq(field)
            if enc_seq:
                for ef in enc_seq.value:
                    if ef.tag_num == 2 and ef.tag_class == 2:  # cipher
                        cipher = unwrap_prim(ef).value
                        if cipher:
                            eccp, _ = parse_der(cipher)
                            eccp_seq = unwrap_seq(eccp)
                            if eccp_seq:
                                ti_field = find_tag(eccp_seq.value, 0, 2)
                                if ti_field:
                                    ti_seq = unwrap_seq(ti_field)
                                    if ti_seq:
                                        for kci in ti_seq.value:
                                            infos.append(parse_krbcredinfo(kci))

    return tickets_raw, infos


# ── CCACHE writer ───────────────────────────────────────────────────

def p_principal(nt, realm, comps):
    buf = struct.pack('>II', nt, len(comps))
    rb = realm.encode('utf-8')
    buf += struct.pack('>I', len(rb)) + rb
    for c in comps:
        cb = c.encode('utf-8')
        buf += struct.pack('>I', len(cb)) + cb
    return buf


def p_keyblock(kt, kv):
    return struct.pack('>hhH', kt, 0, len(kv)) + kv


def p_times(a, s, e, r):
    return struct.pack('>IIII', a, s, e, r)


def p_octet(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return struct.pack('>I', len(data)) + data


def kirbi_to_ccache(data):
    tickets_raw, infos = parse_krbcred(data)
    if not tickets_raw or not infos:
        raise ValueError('No tickets or ticket-info in kirbi')
    info = infos[0]
    tkt_der = tickets_raw[0]

    nt, ns = info.get('pname', (1, ['UNKNOWN']))
    prealm = info.get('prealm', 'UNKNOWN')
    snt, sns = info.get('sname', (1, ['UNKNOWN']))
    srealm = info.get('srealm', 'UNKNOWN')

    # Same trim that minikerberos does
    if len(sns) > 2 and sns[-1].upper() == srealm.upper():
        sns = sns[:-1]

    kt, kv = info.get('key', (0, b''))
    flags = info.get('flags', 0)

    # Build ccache
    cc = struct.pack('>H', 0x0504)  # version (KRB5_FCC_FVNO_4)
    hdr = struct.pack('>HH', 1, 8) + b'\x00' * 8
    cc += struct.pack('>H', len(hdr)) + hdr
    cc += p_principal(nt, prealm, ns)    # primary principal
    cc += p_principal(nt, prealm, ns)    # client
    cc += p_principal(snt, srealm, sns)  # server
    cc += p_keyblock(kt, kv)
    cc += p_times(
        info.get('authtime', 0), info.get('starttime', 0),
        info.get('endtime', 0), info.get('renew_till', 0))
    cc += struct.pack('<B', 0)     # is_skey
    cc += struct.pack('<I', flags) # tktflags (little-endian!)
    cc += struct.pack('>I', 0)    # num_address
    cc += struct.pack('>I', 0)    # num_authdata
    cc += p_octet(tkt_der)
    cc += p_octet(b'')            # second_ticket
    return cc


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f'Usage:  {sys.argv[0]}  <input.kirbi>  [output.ccache]', file=sys.stderr)
        sys.exit(1)

    inpath = sys.argv[1]
    outpath = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(inpath)[0] + '.ccache'

    with open(inpath, 'rb') as f:
        raw = f.read()

    # Try binary first, then base64 (Rubeus format)
    try:
        cc = kirbi_to_ccache(raw)
    except Exception:
        try:
            raw = base64.b64decode(raw.decode('ascii').strip())
            cc = kirbi_to_ccache(raw)
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)

    with open(outpath, 'wb') as f:
        f.write(cc)
    print(f'Wrote {outpath}  ({len(cc)} bytes)')


if __name__ == '__main__':
    main()

"""
test command
uv run kirbi2ccache.py "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/tgt.kirbi"  "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/krb5cc_1000"

"""