"""Tests for the standalone kirbi2ccache.py converter."""
import base64
import pathlib
import struct
import sys
import tempfile
import subprocess
import pytest

from config import get_testfiles_kirbi, KIRBI_DIR
from ktconvertor.kirbi2ccache import kirbi_to_ccache

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "src/ktconvertor" / 'kirbi2ccache.py'

# Import the module under test by loading it as a module
import importlib.util
spec = importlib.util.spec_from_file_location('kirbi2ccache', SCRIPT)
k2c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k2c)


# ── DER TLV parser ────────────────────────────────────────────────────────

class TestParseDER:
    def test_integer(self):
        """parse_der handles INTEGER (tag 0x02)."""
        data = b'\x02\x01\x2a'  # INTEGER 42
        tlv, end = k2c.parse_der(data)
        assert tlv.tag == 0x02
        assert tlv.value == 42
        assert end == 3

    def test_negative_integer(self):
        """parse_der handles negative INTEGER."""
        data = b'\x02\x01\xfe'  # INTEGER -2
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == -2

    def test_multi_byte_integer(self):
        """parse_der handles multi-byte INTEGER."""
        data = b'\x02\x02\x01\x00'  # INTEGER 256
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 256

    def test_octet_string(self):
        """parse_der handles OCTET STRING (tag 0x04)."""
        data = b'\x04\x05hello'
        tlv, _ = k2c.parse_der(data)
        assert tlv.tag == 0x04
        assert tlv.value == b'hello'

    def test_octet_string_empty(self):
        """parse_der handles empty OCTET STRING."""
        data = b'\x04\x00'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == b''

    def test_bit_string(self):
        """parse_der parses BIT STRING (tag 0x03) as int."""
        # BIT STRING with 0 unused bits, value 0x40E10000
        # todo test not pass
        data = b'\x03\x05\x00\x40\xe1\x00\x00'
        tlv, _ = k2c.parse_der(data)
        assert tlv.tag == 0x03
        assert tlv.value == 0x40E10000

    def test_bit_string_trailing_zeros(self):
        """Trailing zero bytes are not stripped (they are part of the value)."""
        # BIT STRING 0x00000001 with 0 unused bits
        data = b'\x03\x05\x00\x00\x00\x00\x01'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 0x00000001

    def test_bit_string_nonzero_unused(self):
        """BIT STRING with non-zero unused bits shifts the value."""
        # 3 unused bits, value bytes = 0x50A00000, after shift = 0x0A140000
        # todo test not pass
        data = b'\x03\x05\x03\x50\xa0\x00\x00'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 0x50A00000 >> 3

    def test_null(self):
        """parse_der handles NULL (tag 0x05)."""
        data = b'\x05\x00'
        tlv, _ = k2c.parse_der(data)
        assert tlv.tag == 0x05
        assert tlv.value is None

    def test_utf8_string(self):
        """parse_der handles UTF8String (tag 0x0C)."""
        data = b'\x0c\x0bTEST.CORP'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 'TEST.CORP'

    def test_utf8_string_unicode(self):
        """parse_der handles UTF8String with unicode."""
        data = b'\x0c\x06caf\xc3\xa9'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 'café'

    def test_general_string(self):
        """parse_der handles GeneralString (tag 0x1B)."""
        data = b'\x1b\x05hello'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == 'hello'

    def test_generalized_time(self):
        """parse_der handles GeneralizedTime (tag 0x18)."""
        data = b'\x18\x0f20240720114417Z'
        tlv, _ = k2c.parse_der(data)
        assert tlv.value == '20240720114417Z'

    def test_sequence_empty(self):
        """parse_der handles empty SEQUENCE."""
        data = b'\x30\x00'
        tlv, _ = k2c.parse_der(data)
        assert tlv.tag == 0x30
        assert tlv.value == []

    def test_sequence_of_integers(self):
        """parse_der parses SEQUENCE OF INTEGER."""
        data = b'\x30\x06\x02\x01\x01\x02\x01\x02'
        tlv, _ = k2c.parse_der(data)
        assert len(tlv.value) == 2
        assert tlv.value[0].value == 1
        assert tlv.value[1].value == 2

    def test_sequence_absolute_offsets(self):
        """parse_der records absolute byte offsets (not slice-relative).

        This is critical: child TLVs must store offsets relative to the
        original data buffer, not to inner slices, so that
        data[tlv.start:tlv.end] extracts the correct bytes.
        """
        # SEQUENCE { INTEGER 5, INTEGER 6, OCTET STRING "abc" }
        # Content: 02 01 05  02 01 06  04 03 61 62 63 = 11 bytes
        data = b'\x30\x0b\x02\x01\x05\x02\x01\x06\x04\x03abc'
        tlv, _ = k2c.parse_der(data)
        assert tlv.start == 0
        assert tlv.end == 13
        # First child: INTEGER 5 at offset 2-4
        c0 = tlv.value[0]
        assert c0.start == 2
        assert c0.end == 5
        assert data[c0.start:c0.end] == b'\x02\x01\x05'
        # Second child: INTEGER 6 at offset 5-7
        c1 = tlv.value[1]
        assert c1.start == 5
        assert c1.end == 8
        assert data[c1.start:c1.end] == b'\x02\x01\x06'
        # Third child: OCTET STRING 'abc' at offset 8-13
        c2 = tlv.value[2]
        assert c2.start == 8
        assert c2.end == 13
        assert data[c2.start:c2.end] == b'\x04\x03abc'

    def test_constructed_context_tag(self):
        """parse_der handles constructed context-specific [APPLICATION n]."""
        # [APPLICATION 0] wrapping INTEGER 42
        data = b'\x60\x03\x02\x01\x2a'
        tlv, _ = k2c.parse_der(data)
        assert tlv.constructed
        assert tlv.tag_class == 1  # application
        assert tlv.tag_num == 0
        assert len(tlv.value) == 1
        assert tlv.value[0].value == 42

    def test_long_form_length(self):
        """parse_der handles long-form length encoding."""
        # INTEGER with value using 2-byte long-form length
        data = b'\x02\x81\x80' + b'\x01' * 128
        tlv, end = k2c.parse_der(data)
        assert tlv.tag == 0x02
        assert end == 3 + 128

    def test_long_form_length_2bytes(self):
        """parse_der handles 2-byte long-form length."""
        val = b'\x02\x82\x01\x00' + b'\x2a' * 256
        tlv, end = k2c.parse_der(val)
        assert end == 4 + 256

    def test_nested_sequence_offsets(self):
        """parse_der handles nested SEQUENCE with correct offsets."""
        # SEQUENCE { SEQUENCE { INTEGER 1 }, INTEGER 2 }
        inner = b'\x30\x03\x02\x01\x01'           # SEQUENCE { INTEGER 1 }
        outer = b'\x30' + bytes([len(inner) + 3])  # outer SEQUENCE
        outer += inner + b'\x02\x01\x02'           # + INTEGER 2
        tlv, _ = k2c.parse_der(outer)
        assert len(tlv.value) == 2
        inner_tlv = tlv.value[0]
        assert inner_tlv.start == 2
        assert inner_tlv.end == 7
        assert outer[inner_tlv.start:inner_tlv.end] == inner
        assert tlv.value[1].value == 2

    def test_unknown_primitive_tag(self):
        """parse_der returns raw bytes for unknown primitive tags."""
        data = b'\x01\x01\xff'  # BOOLEAN TRUE (tag 0x01, not handled)
        tlv, _ = k2c.parse_der(data)
        assert tlv.tag == 0x01
        assert tlv.value == b'\xff'


# ── Navigator functions ──────────────────────────────────────────────────

class TestNavigators:
    def test_find_tag_found(self):
        """find_tag returns the matching child."""
        children = [
            k2c.TLV(0x60, 0, 3, [k2c.TLV(0x02, 1, 3, 42)]),
            k2c.TLV(0x61, 3, 6, [k2c.TLV(0x04, 4, 6, b'x')]),
        ]
        result = k2c.find_tag(children, 0, 1)
        assert result is not None
        assert result.tag == 0x60

    def test_find_tag_not_found(self):
        """find_tag returns None when no match."""
        children = [k2c.TLV(0x60, 0, 3, [])]
        assert k2c.find_tag(children, 99, 1) is None

    def test_unwrap_seq(self):
        """unwrap_seq returns the inner SEQUENCE."""
        inner = k2c.TLV(0x30, 1, 5, [])
        outer = k2c.TLV(0x60, 0, 5, [inner])
        assert k2c.unwrap_seq(outer) is inner

    def test_unwrap_seq_non_constructed(self):
        """unwrap_seq returns None for primitive TLVs."""
        tlv = k2c.TLV(0x02, 0, 3, 42)
        assert k2c.unwrap_seq(tlv) is None

    def test_unwrap_prim(self):
        """unwrap_prim returns the inner value."""
        inner = k2c.TLV(0x02, 1, 3, 99)
        outer = k2c.TLV(0x61, 0, 3, [inner])
        assert k2c.unwrap_prim(outer) is inner


# ── KerberosTime parser ──────────────────────────────────────────────────

class TestKerberosTime:
    def test_parse_standard(self):
        """parse_kerberostime handles standard GeneralizedTime."""
        result = k2c.parse_kerberostime('20240720114417Z')
        assert result == 1721475857

    def test_parse_with_milliseconds(self):
        """parse_kerberostime truncates fractional seconds."""
        result = k2c.parse_kerberostime('20240720114417.123Z')
        assert result == 1721475857

    def test_parse_empty(self):
        """parse_kerberostime returns 0 for empty input."""
        assert k2c.parse_kerberostime('') == 0

    def test_parse_invalid(self):
        """parse_kerberostime returns 0 for unparseable input."""
        assert k2c.parse_kerberostime('not-a-time') == 0

    def test_parse_epoch(self):
        """parse_kerberostime handles epoch."""
        result = k2c.parse_kerberostime('19700101000000Z')
        assert result == 0


# ── Principal parser ─────────────────────────────────────────────────────

class TestParsePrincipal:
    def _context_seq(self, children):
        """Build a SEQUENCE of context-specific implicit tags as in real kirbi."""
        return k2c.TLV(0x30, 0, 0, children)

    def _ctx_prim(self, tag_num, value_bytes):
        """Context-specific primitive implicit tag (unused bits for BIT STRING)."""
        tag_byte = 0x80 | tag_num
        return k2c.TLV(tag_byte, 0, len(value_bytes) + 2, value_bytes)

    def _ctx_constructed_int(self, tag_num, val):
        """Context tag [n] wrapping INTEGER, as seen in PrincipalName name-type."""
        inner = k2c.TLV(0x02, 0, 0, val)
        # Constructed context tag: 0xa0 | tag_num
        tag_byte = 0xa0 | tag_num
        return k2c.TLV(tag_byte, 0, 0, [inner])

    def _ctx_constructed_seq(self, tag_num, children):
        """Context tag [n] wrapping a SEQUENCE."""
        tag_byte = 0xa0 | tag_num
        return k2c.TLV(tag_byte, 0, 0, children)

    def test_simple_principal(self):
        """parse_principal extracts type and name-strings from PrincipalName."""
        # PrincipalName ::= SEQUENCE {
        #   name-type   [0] INTEGER  (implicit → 0x80/0xa0 wrapping)
        #   name-string [1] SEQUENCE OF KerberosString  (implicit → 0xa1 wrapping SEQUENCE OF)
        # }
        # In real DER, name-type is context [0] wrapping INTEGER
        # name-string is context [1] wrapping SEQUENCE OF GeneralString

        # name-type [0] constructed wrapping INTEGER 1
        nt_field = k2c.TLV(0xa0, 0, 5, [k2c.TLV(0x02, 2, 5, 1)])

        # name-string [1] constructed wrapping SEQUENCE { GeneralString "victim" }
        gs = k2c.TLV(0x1b, 0, 6, 'victim')
        inner_seq = k2c.TLV(0x30, 0, 8, [gs])
        ns_field = k2c.TLV(0xa1, 0, 10, [inner_seq])

        pseq = k2c.TLV(0x30, 0, 15, [nt_field, ns_field])
        nt, ns = k2c.parse_principal(pseq)
        assert nt == 1
        assert ns == ['victim']

    def test_multi_component(self):
        """parse_principal handles multi-component names."""
        nt_field = k2c.TLV(0xa0, 0, 5, [k2c.TLV(0x02, 2, 5, 1)])

        gs1 = k2c.TLV(0x1b, 0, 6, 'krbtgt')
        gs2 = k2c.TLV(0x1b, 0, 9, 'TEST.CORP')
        inner_seq = k2c.TLV(0x30, 0, 17, [gs1, gs2])
        ns_field = k2c.TLV(0xa1, 0, 19, [inner_seq])

        pseq = k2c.TLV(0x30, 0, 24, [nt_field, ns_field])
        nt, ns = k2c.parse_principal(pseq)
        assert nt == 1
        assert ns == ['krbtgt', 'TEST.CORP']


# ── KrbCredInfo parser ───────────────────────────────────────────────────

class TestParseKrbCredInfo:
    def test_parse_full(self):
        """parse_krbcredinfo extracts all fields from a KrbCredInfo."""
        # Build a KrbCredInfo SEQUENCE with context-specific implicit tags
        # matching the real kirbi DER structure.

        # key [0] → EncryptionKey SEQUENCE { keytype [0] INTEGER 18, keyvalue [1] OCTET STRING (32 bytes) }
        kt_inner = k2c.TLV(0x02, 0, 3, 18)
        kt_field = k2c.TLV(0xa0, 0, 5, [kt_inner])
        kv_inner = k2c.TLV(0x04, 0, 34, b'\x01' * 32)
        kv_field = k2c.TLV(0xa1, 0, 36, [kv_inner])
        key_seq = k2c.TLV(0x30, 0, 41, [kt_field, kv_field])
        key_field = k2c.TLV(0xa0, 0, 43, [key_seq])

        # prealm [1] GeneralString "TEST.CORP"
        prealm_inner = k2c.TLV(0x1b, 0, 9, 'TEST.CORP')
        prealm_field = k2c.TLV(0xa1, 0, 11, [prealm_inner])

        seq_tlv = k2c.TLV(0x30, 0, 54, [key_field, prealm_field])
        info = k2c.parse_krbcredinfo(seq_tlv)
        assert info['key'] == (18, b'\x01' * 32)
        assert info['prealm'] == 'TEST.CORP'


# ── CCACHE serialization ─────────────────────────────────────────────────

class TestPrincipalSerialization:
    def test_simple_principal(self):
        """p_principal produces correct big-endian format."""
        result = k2c.p_principal(1, 'TEST.CORP', ['victim'])
        # type(4) + count(4) + realm_len(4) + "TEST.CORP"(9) + comp_len(4) + "victim"(6)
        assert len(result) == 4 + 4 + 4 + 9 + 4 + 6
        assert struct.unpack('>I', result[0:4])[0] == 1
        assert struct.unpack('>I', result[4:8])[0] == 1
        realm_len = struct.unpack('>I', result[8:12])[0]
        assert result[12:12+realm_len] == b'TEST.CORP'
        comp_len = struct.unpack('>I', result[12+realm_len:12+realm_len+4])[0]
        assert result[12+realm_len+4:12+realm_len+4+comp_len] == b'victim'

    def test_two_component(self):
        """p_principal handles multi-component names."""
        result = k2c.p_principal(1, 'TEST.CORP', ['krbtgt', 'TEST.CORP'])
        count = struct.unpack('>I', result[4:8])[0]
        assert count == 2

    def test_empty_realm(self):
        """p_principal handles empty realm."""
        result = k2c.p_principal(1, '', ['user'])
        assert len(result) == 4 + 4 + 4 + 0 + 4 + 4  # type + count + realm_len + comp

    def test_empty_components(self):
        """p_principal handles empty component list."""
        result = k2c.p_principal(1, 'REALM', [])
        # type(4) + count(4=0) + realm_len(4) + "REALM"(5)
        assert len(result) == 4 + 4 + 4 + 5


class TestKeyblockSerialization:
    def test_aes256_key(self):
        """p_keyblock serializes AES-256 key correctly."""
        key = b'\x01' * 32
        result = k2c.p_keyblock(18, key)
        # keytype(2) + etype(2) + keylen(2) + key(32)
        assert len(result) == 2 + 2 + 2 + 32
        kt, etype, klen = struct.unpack('>hhH', result[:6])
        assert kt == 18
        assert etype == 0
        assert klen == 32
        assert result[6:] == key

    def test_rc4_key(self):
        """p_keyblock serializes RC4 key correctly."""
        key = b'\x01' * 16
        result = k2c.p_keyblock(23, key)
        assert len(result) == 2 + 2 + 2 + 16
        kt, _, klen = struct.unpack('>hhH', result[:6])
        assert kt == 23
        assert klen == 16


class TestTimesSerialization:
    def test_times(self):
        """p_times writes 4 big-endian uint32s."""
        result = k2c.p_times(0, 100, 200, 300)
        assert len(result) == 16
        a, s, e, r = struct.unpack('>IIII', result)
        assert a == 0
        assert s == 100
        assert e == 200
        assert r == 300


class TestOctetSerialization:
    def test_octet_bytes(self):
        """p_octet writes 4-byte length prefix + data."""
        result = k2c.p_octet(b'hello')
        assert len(result) == 4 + 5
        assert result[:4] == struct.pack('>I', 5)
        assert result[4:] == b'hello'

    def test_octet_string(self):
        """p_octet encodes str as UTF-8."""
        result = k2c.p_octet('héllo')
        expected = 'héllo'.encode('utf-8')
        assert len(result) == 4 + len(expected)
        assert result[4:] == expected

    def test_octet_empty(self):
        """p_octet handles empty data."""
        result = k2c.p_octet(b'')
        assert result == b'\x00\x00\x00\x00'


# ── End-to-end conversion ────────────────────────────────────────────────

class TestKirbiToCCache:
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.kirbi_files = list(get_testfiles_kirbi())

    def test_all_kirbis_produce_valid_ccache(self):
        """Every test kirbi converts to a valid ccache parseable by minikerberos."""
        from minikerberos.common.ccache import CCACHE
        for f in self.kirbi_files:
            with open(f, 'rb') as fh:
                raw = fh.read()
            cc_bytes = k2c.kirbi_to_ccache(raw)
            cc = CCACHE.from_bytes(cc_bytes)
            assert len(cc.credentials) == 1
            cred = cc.credentials[0]
            assert cred.client is not None
            assert cred.server is not None
            assert cred.key.keytype is not None
            assert cred.ticket is not None
            assert len(cred.ticket.data) > 0

    def test_ticket_der_is_valid(self):
        """The ticket in the ccache is a valid DER-encoded Ticket."""
        from minikerberos.protocol.asn1_structs import Ticket
        from minikerberos.common.ccache import CCACHE
        for f in self.kirbi_files:
            with open(f, 'rb') as fh:
                raw = fh.read()
            cc_bytes = k2c.kirbi_to_ccache(raw)
            cc = CCACHE.from_bytes(cc_bytes)
            cred = cc.credentials[0]
            # This will raise if the DER is invalid
            Ticket.load(cred.ticket.data)

    def test_principal_names_match(self):
        """Client and server principal names correspond between kirbi and ccache."""
        from minikerberos.common.ccache import CCACHE
        from minikerberos.common.kirbi import Kirbi
        for f in self.kirbi_files:
            kirbi = Kirbi.from_file(f)
            cc_bytes = k2c.kirbi_to_ccache(open(f, 'rb').read())
            cc = CCACHE.from_bytes(cc_bytes)
            cred = cc.credentials[0]

            native = kirbi.kirbiobj.native
            enc = native['enc-part']['cipher']
            from minikerberos.protocol.asn1_structs import EncKrbCredPart
            ecred = EncKrbCredPart.load(enc).native
            ti = ecred['ticket-info'][0]

            client_str = cred.client.to_string()
            pname_str = '/'.join(ti['pname']['name-string'])
            assert pname_str.split('/')[0] in client_str, \
                f'{f.name}: {pname_str} not in {client_str}'

            server_str = cred.server.to_string()
            sname_str = '/'.join(ti['sname']['name-string'])
            # The sname may have the realm trimmed as last component
            sname_core = sname_str.split('/')[0]
            assert sname_core in server_str, \
                f'{f.name}: {sname_core} not in {server_str}'

    def test_session_key_type_and_size(self):
        """Session key type and value match between kirbi and ccache."""
        from minikerberos.common.ccache import CCACHE
        from minikerberos.common.kirbi import Kirbi
        for f in self.kirbi_files:
            kirbi = Kirbi.from_file(f)
            cc_bytes = k2c.kirbi_to_ccache(open(f, 'rb').read())
            cc = CCACHE.from_bytes(cc_bytes)
            cred = cc.credentials[0]

            native = kirbi.kirbiobj.native
            enc = native['enc-part']['cipher']
            from minikerberos.protocol.asn1_structs import EncKrbCredPart
            ecred = EncKrbCredPart.load(enc).native
            ti = ecred['ticket-info'][0]

            assert cred.key.keytype == ti['key']['keytype']
            assert cred.key.keyvalue == ti['key']['keyvalue']

    def test_times_match(self):
        """Ticket times match between kirbi and ccache."""
        from minikerberos.common.ccache import CCACHE
        from minikerberos.common.kirbi import Kirbi
        for f in self.kirbi_files:
            kirbi = Kirbi.from_file(f)
            cc_bytes = k2c.kirbi_to_ccache(open(f, 'rb').read())
            cc = CCACHE.from_bytes(cc_bytes)
            cred = cc.credentials[0]

            native = kirbi.kirbiobj.native
            enc = native['enc-part']['cipher']
            from minikerberos.protocol.asn1_structs import EncKrbCredPart
            ecred = EncKrbCredPart.load(enc).native
            ti = ecred['ticket-info'][0]

            # Convert KerberosTime to timestamp
            def kerbtime(kt):
                if kt is None:
                    return 0
                return int(kt.timestamp())

            assert cred.time.authtime == kerbtime(ti.get('authtime'))
            assert cred.time.endtime == kerbtime(ti.get('endtime'))

    def test_file_format_version(self):
        """CCACHE version is 0x0504 (KRB5_FCC_FVNO_4)."""
        for f in self.kirbi_files:
            with open(f, 'rb') as fh:
                raw = fh.read()
            cc_bytes = k2c.kirbi_to_ccache(raw)
            ver = struct.unpack('>H', cc_bytes[0:2])[0]
            assert ver == 0x0504

    def test_output_size_is_consistent(self):
        """Conversion of the same kirbi always produces the same ccache."""
        for f in self.kirbi_files:
            with open(f, 'rb') as fh:
                raw = fh.read()
            cc1 = k2c.kirbi_to_ccache(raw)
            cc2 = k2c.kirbi_to_ccache(raw)
            assert cc1 == cc2

    def test_round_trip_via_minikerberos(self):
        """CCache produced by script is re-parseable by minikerberos and
        preserves all credential fields through another kirbi round-trip."""
        from minikerberos.common.ccache import CCACHE
        for f in self.kirbi_files:
            with open(f, 'rb') as fh:
                raw = fh.read()
            cc_bytes = k2c.kirbi_to_ccache(raw)
            cc = CCACHE.from_bytes(cc_bytes)
            # Convert back to kirbi, then to ccache again
            kirbi2, _ = cc.credentials[0].to_kirbi()
            cc2 = CCACHE.from_kirbi(kirbi2)
            cred2 = cc2.credentials[0]
            # Client, server, key should match
            assert cred2.client.to_string() == cc.credentials[0].client.to_string()
            assert cred2.key.keytype == cc.credentials[0].key.keytype
            assert cred2.key.keyvalue == cc.credentials[0].key.keyvalue



# ── Edge cases ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_invalid_der_truncated(self):
        """parse_der raises on truncated data."""
        with pytest.raises((IndexError, struct.error)):
            k2c.parse_der(b'\x30\x05\x02\x01')

    def test_invalid_der_bad_length(self):
        """parse_der handles data shorter than declared length."""
        with pytest.raises((IndexError, struct.error)):
            k2c.parse_der(b'\x30\xff')

    def test_kirbi_with_renew_till(self):
        """parse_krbcredinfo extracts renew_till field."""
        # authtime [4] context tag 0xa4, endtime [6] context tag 0xa6, renew_till [7] context tag 0xa7
        # todo test not pass
        seq = k2c.TLV(0x30, 0, 24, [
            k2c.TLV(0xa4, 0, 12, [k2c.TLV(0x18, 1, 12, '20240720114417Z')]),
            k2c.TLV(0xa7, 12, 24, [k2c.TLV(0x18, 13, 24, '20250720114417Z')]),
        ])
        info = k2c.parse_krbcredinfo(seq)
        assert info['authtime'] == 1721475857
        assert info['renew_till'] == 1753011857

    def test_kirbi_without_flags(self):
        """parse_krbcredinfo handles missing optional flags."""
        seq = k2c.TLV(0x30, 0, 0, [])
        info = k2c.parse_krbcredinfo(seq)
        assert 'flags' not in info

    def test_empty_principal_name_string(self):
        """p_principal handles empty name-string component."""
        result = k2c.p_principal(1, 'R', [''])
        comp_offset = 4 + 4 + 4 + 1  # type + count + realm_len + 'R'
        comp_len = struct.unpack('>I', result[comp_offset:comp_offset+4])[0]
        assert comp_len == 0

    def test_unicode_realm(self):
        """p_principal encodes realm as UTF-8."""
        result = k2c.p_principal(1, 'Café', ['user'])
        realm_offset = 4 + 4  # type + count
        realm_len = struct.unpack('>I', result[realm_offset:realm_offset+4])[0]
        realm = result[realm_offset+4:realm_offset+4+realm_len]
        assert realm == 'Café'.encode('utf-8')

    def test_unicode_component(self):
        """p_principal encodes name components as UTF-8."""
        result = k2c.p_principal(1, 'R', ['usér'])
        comp_offset = 4 + 4 + 4 + 1  # type + count + realm_len + 'R'
        comp_len = struct.unpack('>I', result[comp_offset:comp_offset+4])[0]
        comp = result[comp_offset+4:comp_offset+4+comp_len]
        assert comp == 'usér'.encode('utf-8')


# ── Negative tests ───────────────────────────────────────────────────────

class TestNegativeCases:
    def test_no_tickets_raises(self):
        """kirbi_to_ccache raises on KRBCRED with no tickets."""
        # Minimal KRBCRED with empty tickets list and no enc-part
        # [APP 22] SEQUENCE { pvno [0] INTEGER 5, msg-type [1] INTEGER 22, tickets [2] SEQUENCE OF {} }
        data = b'\x7e\x19\x30\x17\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x16\xa2\x0b\x30\x09\x30\x07\xa0\x03\x02\x01\x12\xa1\x04\x04\x02\x00\x00'
        with pytest.raises(ValueError, match='No tickets'):
            k2c.kirbi_to_ccache(data)

    def test_empty_kirbi_raises(self):
        """kirbi_to_ccache raises on empty data."""
        with pytest.raises((IndexError, ValueError)):
            k2c.kirbi_to_ccache(b'')

    @pytest.mark.skip(reason="base64 decode doesn't validate structure")
    def test_garbage_base64(self):
        """kirbi_to_ccache raises on garbage after base64 fallback."""
        with pytest.raises(Exception):
            k2c.kirbi_to_ccache(b'!!not-base64!!')


def test_cli_example():
    inpath = "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/tgt.kirbi"
    outpath = "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/krb5cc_1000"

    with open(inpath, 'rb') as f:
        raw = f.read()

    # Try binary first, then base64
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