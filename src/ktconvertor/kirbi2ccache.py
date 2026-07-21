"""Standalone .kirbi to MIT ccache credential converter.

This module parses a Kerberos V5 KRB-CRED (.kirbi) structure—often exported by
tools like Rubeus—and reconstructs it into a standard MIT ccache file usable by
native Kerberos stacks and Hadoop/HDFS clients.

Zero dependencies beyond the Python standard library.

Usage:
  python kirbi2ccache.py ticket.kirbi            # writes ticket.ccache
  python kirbi2ccache.py ticket.kirbi out.ccache  # writes out.ccache
  python kirbi2ccache.py input.kirbi             # also handles base64 (Rubeus)
"""

from __future__ import annotations

import base64
import datetime
import os
import struct
import sys
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple, Union

# ── Type Aliases for Enhanced Scannability ───────────────────────────
PrincipalInfo = Tuple[int, List[str]]
KeyBlock = Tuple[int, bytes]
KrbCredInfo = Dict[str, Any]


# ── Minimal DER TLV parser ──────────────────────────────────────────
class ASN1Class(IntEnum):
    """ASN.1 Tag Classes stored in Bits 7-6 of the Identifier Octet."""
    UNIVERSAL = 0  # 0b00
    APPLICATION = 1  # 0b01
    CONTEXT = 2  # 0b10
    PRIVATE = 3  # 0b11


class TLV:
    """
    Represents an ASN.1 DER Tag-Length-Value node with absolute data offsets.
    """
    # Bit masks for ASN.1 Identifier Octets
    CLASS_MASK = 0xC0  # Bits 7-6: 1100 0000
    CONSTRUCTED_MASK = 0x20  # Bit 5:    0010 0000
    TAG_NUM_MASK = 0x1F  # Bits 4-0: 0001 1111

    __slots__ = ('tag', 'start', 'end', 'tag_class', 'constructed', 'tag_num', 'value')

    # In ASN.1 DER, every piece of data starts with an Identifier Octet (a single 8-bit byte).
    # Rather than using a full byte for every piece of metadata, the creators of ASN.1 compressed three
    # different pieces of information into that single 8-bit byte:
    # """ Bit Position:   7   6   |   5   |   4   3   2   1   0
    #                   ----------+-------+---------------------
    #      Field Name:    Class    | Type  |     Tag Number"""
    def __init__(self, tag: int, start: int, end: int, value: Any) -> None:
        self.tag: int = tag
        self.start: int = start
        self.end: int = end

        # Extracts the Tag Class stored in the highest 2 bits (bits 7 and 6) of the byte
        # >> 6 means pushes all bits in the byte to the right by 6 positions, discarding the bottom 6 bits entirely.
        # for example
        # Original Byte:   1 0 0 0 0 0 0 0  (Binary for 0x80)
        # Shift right 6:   0 0 0 0 0 0 1 0  (Shifted 6 positions to the right)

        # Result Decimal:  2                (Context-specific class)
        self.tag_class: ASN1Class = ASN1Class((tag & self.CLASS_MASK) >> 6)
        self.constructed: bool = bool(tag & self.CONSTRUCTED_MASK)
        self.tag_num: int = tag & self.TAG_NUM_MASK
        self.value: Any = value

    def __repr__(self) -> str:
        return (
            f"TLV(tag=0x{self.tag:02x}, class={self.tag_class.name}, "
            f"constructed={self.constructed}, num={self.tag_num})"
        )


def parse_der(data: bytes, offset: int = 0) -> Tuple[TLV, int]:
    """
    Parses a single ASN.1 DER element from a byte string using absolute offsets.
    :param data: The complete raw input bytes.
    :param offset: The absolute starting index to parse from.
    :return: A tuple containing the parsed TLV object and the next absolute offset integer.
    """
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
        value_list: List[TLV] = []
        o = offset
        while o < end:
            child, o = parse_der(data, o)
            value_list.append(child)
        value = value_list
    else:
        value = data[offset:end]

    return TLV(tag, start, end, value), end


# ── Navigators ──────────────────────────────────────────────────────

def find_tag(children: List[TLV], tag_num: int, tag_class: int = 2) -> Optional[TLV]:
    """
    Searches a list of TLV nodes for a specific tag number and class.
    :param children: A list of TLV objects to inspect.
    :param tag_num: The target identifier tag number.
    :param tag_class: The expected class bits (defaults to 2 for context-specific).
    :return: The matching TLV object if found, otherwise None.
    """
    for c in children:
        if c.tag_num == tag_num and c.tag_class == tag_class:
            return c
    return None


def unwrap_seq(tlv: TLV) -> Optional[TLV]:
    """
    Extracts the inner SEQUENCE element wrapped inside a constructed node.
    :param tlv: The outer constructed TLV node container.
    :return: The primary inner child TLV object if constructed, otherwise None.
    """
    if tlv.constructed and len(tlv.value) > 0:
        return tlv.value[0]
    return None


def unwrap_prim(tlv: TLV) -> Optional[TLV]:
    """
    Extracts the internal primitive TLV leaf element from a context tag wrapper.
    :param tlv: The outer contextual TLV wrapper node.
    :return: The core inner child TLV object, or None if empty or unconstructed.
    """
    if tlv.constructed and len(tlv.value) > 0:
        return tlv.value[0]
    return None


# ── Parsers ─────────────────────────────────────────────────────────

def parse_principal(seq_tlv: TLV) -> PrincipalInfo:
    """
    Parses a Kerberos Principal name sequence structure.
    :param seq_tlv: The TLV object representing the Principal sequence block.
    :return: A tuple containing the type integer and list of string components.
    """
    nt = 0
    ns: List[str] = []
    for c in seq_tlv.value:
        if c.tag_num == 0 and c.tag_class == 2:
            nt = unwrap_prim(c).value
        elif c.tag_num == 1 and c.tag_class == 2:
            seq_of = unwrap_seq(c)
            if seq_of:
                for s in seq_of.value:
                    ns.append(s.value)
    return nt, ns


def parse_kerberostime(gt_str: Optional[str]) -> int:
    """
    Converts a standard Kerberos GeneralizedTime string into a Unix epoch timestamp.
    :param gt_str: The raw ASN.1 timestamp string (e.g., '20260717114425Z').
    :return: An integer representing the Unix timestamp, or 0 if parsing fails or input is empty.
    """
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


def parse_krbcredinfo(seq_tlv: TLV) -> KrbCredInfo:
    """
    Maps fields from a KrbCredInfo sequence block into a key-value dictionary.
    :param seq_tlv: The TLV representation of the individual KrbCredInfo sequence block.
    :return: A dictionary containing extracted metadata fields such as times, names, and keys.
    """
    info: KrbCredInfo = {}
    for c in seq_tlv.value:
        if c.tag_num == 0 and c.tag_class == 2:  # key
            ks = unwrap_seq(c)  # EncryptionKey SEQUENCE
            if ks:
                kt = 0
                kv = b''
                for kf in ks.value:
                    if kf.tag_num == 0 and kf.tag_class == 2:
                        inner_kt = unwrap_prim(kf)
                        if inner_kt:
                            kt = inner_kt.value
                    elif kf.tag_num == 1 and kf.tag_class == 2:
                        inner_kv = unwrap_prim(kf)
                        if inner_kv:
                            kv = inner_kv.value
                info['key'] = (kt, kv)
        elif c.tag_num == 1 and c.tag_class == 2:  # prealm
            inner = unwrap_prim(c)
            if inner:
                info['prealm'] = inner.value
        elif c.tag_num == 2 and c.tag_class == 2:  # pname
            inner_seq = unwrap_seq(c)
            if inner_seq:
                info['pname'] = parse_principal(inner_seq)
        elif c.tag_num == 3 and c.tag_class == 2:  # flags
            inner = unwrap_prim(c)
            if inner:
                info['flags'] = inner.value
        elif c.tag_num == 4 and c.tag_class == 2:  # authtime
            inner = unwrap_prim(c)
            if inner:
                info['authtime'] = parse_kerberostime(inner.value)
        elif c.tag_num == 5 and c.tag_class == 2:  # starttime
            inner = unwrap_prim(c)
            if inner:
                info['starttime'] = parse_kerberostime(inner.value)
        elif c.tag_num == 6 and c.tag_class == 2:  # endtime
            inner = unwrap_prim(c)
            if inner:
                info['endtime'] = parse_kerberostime(inner.value)
        elif c.tag_num == 7 and c.tag_class == 2:  # renew_till
            inner = unwrap_prim(c)
            if inner:
                info['renew_till'] = parse_kerberostime(inner.value)
        elif c.tag_num == 8 and c.tag_class == 2:  # srealm
            inner = unwrap_prim(c)
            if inner:
                info['srealm'] = inner.value
        elif c.tag_num == 9 and c.tag_class == 2:  # sname
            inner_seq = unwrap_seq(c)
            if inner_seq:
                info['sname'] = parse_principal(inner_seq)
    return info


def parse_krbcred(data: bytes) -> Tuple[List[bytes], List[KrbCredInfo]]:
    """
    Extracts raw ticket payloads and credential metadata blocks from a KRB-CRED container.
    :param data: Raw unparsed KRB-CRED file byte array.
    :return: A tuple containing a list of raw ticket byte structures and a list of parsed metadata dicts.
    """
    outer, _ = parse_der(data)
    seq = outer.value[0] if outer.constructed else outer

    tickets_raw: List[bytes] = []
    infos: List[KrbCredInfo] = []

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

def p_principal(nt: int, realm: str, comps: List[str]) -> bytes:
    """
    Serializes a Principal identity component into a standard MIT ccache byte layout.
    :param nt: Name type identifier.
    :param realm: Name of target authentication realm.
    :param comps: List of nested sub-components inside name.
    :return: Packed raw bytes matching the format structure.
    """
    buf = struct.pack('>II', nt, len(comps))
    rb = realm.encode('utf-8')
    buf += struct.pack('>I', len(rb)) + rb
    for c in comps:
        cb = c.encode('utf-8')
        buf += struct.pack('>I', len(cb)) + cb
    return buf


def p_keyblock(kt: int, kv: bytes) -> bytes:
    """
    Packs encryption keyblock type and value dimensions into structural bytes.
    :param kt: Encryption mechanism identifier key type.
    :param kv: The raw sequence payload byte array.
    :return: MIT serialized representation of target key components.
    """
    return struct.pack('>hhH', kt, 0, len(kv)) + kv


def p_times(a: int, s: int, e: int, r: int) -> bytes:
    """
    Packs key lifecycle timestamps into four 32-bit big-endian integers.
    :param a: Authentication timeline anchor index.
    :param s: Active initialization timeline index.
    :param e: Terminal lifecycle bounding index.
    :param r: Extended renewal threshold boundary point.
    :return: Binary representation containing mapped timeline references.
    """
    return struct.pack('>IIII', a, s, e, r)


def p_octet(data: Union[str, bytes]) -> bytes:
    """
    Prefixes data length as a 32-bit big-endian integer over a byte stream.
    :param data: Targeted raw string or raw byte payload array.
    :return: Length-prefixed binary block string layout wrapper.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return struct.pack('>I', len(data)) + data


def kirbi_to_ccache(data: bytes) -> bytes:
    """
    Converts unparsed binary input data from .kirbi format into an MIT ccache structure.
    Raises:
    ValueError: If input credentials do not contain appropriate identity tracks.

    :param data: Clean base64-decoded or direct structural source file contents.
    :return: Fully packed payload ready to write directly to a credential cache destination.

    """
    tickets_raw, infos = parse_krbcred(data)
    if not tickets_raw or not infos:
        raise ValueError('No tickets or ticket-info located within the provided source structure.')
    # todo here we only take the first ticket and discard the rest. We need to be able to process multiple
    # ticket correctly in the future.
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
    cc += p_principal(nt, prealm, ns)  # primary principal
    cc += p_principal(nt, prealm, ns)  # client
    cc += p_principal(snt, srealm, sns)  # server
    cc += p_keyblock(kt, kv)
    cc += p_times(
        info.get('authtime', 0), info.get('starttime', 0),
        info.get('endtime', 0), info.get('renew_till', 0))
    cc += struct.pack('<B', 0)  # is_skey
    cc += struct.pack('<I', flags)  # tktflags (little-endian!)
    cc += struct.pack('>I', 0)  # num_address
    cc += struct.pack('>I', 0)  # num_authdata
    cc += p_octet(tkt_der)
    cc += p_octet(b'')  # second_ticket
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
