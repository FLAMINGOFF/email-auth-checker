"""离线单元测试：不联网，用假的 DNS 数据验证逻辑。运行: python3 -m unittest -v"""
import base64
import io
import json
import struct
import unittest
from contextlib import redirect_stdout
from unittest import mock

import email_auth_check as e


class FakeResolver:
    """用字典模拟 DNS：{(name, type): [记录...]}；值为 DNSError 时抛出。"""
    label = "fake"

    def __init__(self, data):
        self.data = {(k[0].lower(), k[1]): v for k, v in data.items()}
        self.queries = []

    def query(self, name, rtype):
        self.queries.append((name, rtype))
        v = self.data.get((name.lower(), rtype), [])
        if isinstance(v, Exception):
            raise v
        return list(v)


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def rsa_spki(bits):
    """构造一个指定位数的假 RSA SubjectPublicKeyInfo（只需要结构对，不需要是真密钥）。"""
    n = (1 << (bits - 1)) | 1
    nb = b"\x00" + n.to_bytes(bits // 8, "big")
    pkcs1 = tlv(0x30, tlv(0x02, nb) + tlv(0x02, b"\x01\x00\x01"))
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    return tlv(0x30, alg + tlv(0x03, b"\x00" + pkcs1))


def dkim(bits, extra=""):
    return f"v=DKIM1; k=rsa;{extra} p=" + base64.b64encode(rsa_spki(bits)).decode()


GOOD = {
    ("example.com", "MX"): ["10 mx.example.com"],
    ("example.com", "TXT"): ["google-site-verification=abc", "v=spf1 include:_spf.example.net -all"],
    ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
    ("selector1._domainkey.example.com", "TXT"): [dkim(2048)],
}


class DNSWireTests(unittest.TestCase):
    def test_build_query_layout(self):
        q = e.build_query("example.com", e.TYPE_TXT, 0x1234)
        self.assertEqual(q[:4], b"\x12\x34\x01\x00")
        self.assertIn(b"\x07example\x03com\x00\x00\x10\x00\x01", q)
        self.assertTrue(q.endswith(b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"))

    def test_bad_names(self):
        with self.assertRaises(e.DNSError):
            e.encode_name("a..b")
        with self.assertRaises(e.DNSError):
            e.encode_name("x" * 64 + ".com")

    def _response(self, answers, rcode=0, tc=False, qid=7):
        q = e.encode_name("example.com") + struct.pack(">HH", 16, 1)
        flags = 0x8180 | rcode | (0x0200 if tc else 0)
        msg = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 0) + q
        for rtype, rdata in answers:
            msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
        return msg

    def test_parse_txt_multi_string_and_skip_cname(self):
        cname = e.encode_name("other.example.com")
        txt = b"\x05v=spf" + b"\x07" + b"1 -all "[:7]
        msg = self._response([(5, cname), (16, txt)])
        r = e.parse_response(msg, 7, e.TYPE_TXT)
        self.assertEqual(r["answers"], ["v=spf1 -all "])
        self.assertEqual(r["rcode"], 0)

    def test_parse_mx_with_compression(self):
        rdata = struct.pack(">H", 10) + b"\x02mx\xc0\x0c"
        r = e.parse_response(self._response([(15, rdata)]), 7, e.TYPE_MX)
        self.assertEqual(r["answers"], ["10 mx.example.com"])

    def test_id_mismatch_and_pointer_loop(self):
        with self.assertRaises(e.DNSError):
            e.parse_response(self._response([]), 8, e.TYPE_TXT)
        with self.assertRaises(e.DNSError):
            e.read_name(b"\x00" * 12 + b"\xc0\x0c", 12)

    def test_rcode_handling(self):
        self.assertEqual(e.UDPResolver._result("x", "TXT", 3, []), [])
        with self.assertRaises(e.DNSError):
            e.UDPResolver._result("x", "TXT", 2, [])

    def test_udp_falls_back_to_tcp_when_truncated(self):
        r = e.UDPResolver("192.0.2.53", retries=0)
        captured = {}

        def fake_udp(packet):
            captured["qid"] = struct.unpack(">H", packet[:2])[0]
            return self._response([], tc=True, qid=captured["qid"])

        def fake_tcp(packet):
            return self._response([(16, b"\x0bv=spf1 -all")], qid=captured["qid"])

        with mock.patch.object(r, "_udp", fake_udp), mock.patch.object(r, "_tcp", fake_tcp):
            self.assertEqual(r.query("example.com", "TXT"), ["v=spf1 -all"])

    def test_udp_timeout_raises_dnserror(self):
        r = e.UDPResolver("192.0.2.53", retries=1)
        with mock.patch.object(r, "_udp", side_effect=OSError("timed out")):
            with self.assertRaises(e.DNSError):
                r.query("example.com", "TXT")

    def test_doh_txt_unquote(self):
        self.assertEqual(e.parse_doh_txt('"v=spf1 include:a" " -all"'), "v=spf1 include:a -all")
        self.assertEqual(e.parse_doh_txt('"say \\"hi\\" \\059"'), 'say "hi" ;')
        self.assertEqual(e.parse_doh_txt("v=spf1 -all"), "v=spf1 -all")

    def test_doh_resolver(self):
        body = json.dumps({"Status": 0, "Answer": [
            {"type": 5, "data": "x."}, {"type": 16, "data": '"v=DMARC1; p=none"'}]}).encode()
        resp = mock.MagicMock()
        resp.__enter__.return_value.read.return_value = body
        with mock.patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(e.DoHResolver("https://doh.test/q").query("_dmarc.x", "TXT"),
                             ["v=DMARC1; p=none"])

    def test_system_nameserver(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="# x\nnameserver 10.0.0.1\n")):
            self.assertEqual(e.system_nameserver(), "10.0.0.1")
        self.assertIsNone(e.system_nameserver("/nonexistent/resolv.conf"))


class SPFTests(unittest.TestCase):
    def spf(self, record, extra=None):
        data = {("d.test", "TXT"): [record] if isinstance(record, str) else record}
        data.update(extra or {})
        return e.check_spf("d.test", FakeResolver(data))

    def test_good(self):
        s = e.check_spf("example.com", FakeResolver(GOOD))
        self.assertEqual(s.extra["lookups"], 1)
        self.assertFalse([f for f in s.findings if f.level in (e.HIGH, e.WARN)])

    def test_missing_and_multiple(self):
        self.assertIn("SPF_MISSING", self.spf([]).codes())
        self.assertIn("SPF_MULTIPLE", self.spf(["v=spf1 -all", "v=spf1 mx -all"]).codes())

    def test_does_not_match_lookalike_prefix(self):
        self.assertIn("SPF_MISSING", self.spf("v=spf10 -all").codes())

    def test_all_qualifiers(self):
        self.assertIn("SPF_PASS_ALL", self.spf("v=spf1 +all").codes())
        self.assertIn("SPF_PASS_ALL", self.spf("v=spf1 all").codes())
        self.assertIn("SPF_NEUTRAL_ALL", self.spf("v=spf1 ?all").codes())
        self.assertIn("SPF_SOFTFAIL_ALL", self.spf("v=spf1 ~all").codes())
        self.assertIn("SPF_FAIL_ALL", self.spf("v=spf1 -all").codes())
        self.assertIn("SPF_NO_ALL", self.spf("v=spf1 mx").codes())
        self.assertIn("SPF_ALL_NOT_LAST", self.spf("v=spf1 -all mx").codes())

    def test_redirect_counts_and_replaces_all(self):
        s = self.spf("v=spf1 redirect=_spf.d.test", {("_spf.d.test", "TXT"): ["v=spf1 a mx -all"]})
        self.assertNotIn("SPF_NO_ALL", s.codes())
        self.assertEqual(s.extra["lookups"], 3)

    def test_syntax_errors(self):
        self.assertIn("SPF_SYNTAX", self.spf("v=spf1 inclde:x.test -all").codes())
        self.assertIn("SPF_BAD_IP", self.spf("v=spf1 ip4:300.1.1.1 -all").codes())
        self.assertIn("SPF_BROAD_IP", self.spf("v=spf1 ip4:0.0.0.0/0 -all").codes())
        self.assertNotIn("SPF_BROAD_IP", self.spf("v=spf1 -ip4:0.0.0.0/0 -all").codes())
        self.assertIn("SPF_PTR", self.spf("v=spf1 ptr -all").codes())
        self.assertIn("SPF_UNKNOWN_MODIFIER", self.spf("v=spf1 foo=bar -all").codes())

    def test_a_with_prefix_parses(self):
        terms = e.parse_spf_terms("v=spf1 a/24 mx:mail.d.test/28 -all")
        self.assertEqual([(t["name"], t["value"]) for t in terms],
                         [("a", "/24"), ("mx", "mail.d.test/28"), ("all", "")])

    def test_too_many_lookups(self):
        extra = {(f"i{n}.test", "TXT"): ["v=spf1 a mx ~all"] for n in range(5)}
        rec = "v=spf1 " + " ".join(f"include:i{n}.test" for n in range(5)) + " -all"
        s = self.spf(rec, extra)
        self.assertEqual(s.extra["lookups"], 15)
        self.assertIn("SPF_TOO_MANY_LOOKUPS", s.codes())

    def test_near_limit(self):
        self.assertIn("SPF_LOOKUPS_NEAR_LIMIT", self.spf("v=spf1 " + "a " * 9 + "-all").codes())

    def test_include_missing_and_loop(self):
        s = self.spf("v=spf1 include:gone.test -all")
        self.assertIn("SPF_INCLUDE_MISSING", s.codes())
        s = self.spf("v=spf1 include:loop.test -all",
                     {("loop.test", "TXT"): ["v=spf1 include:d.test -all"]})
        self.assertIn("SPF_LOOP", s.codes())

    def test_void_lookups(self):
        rec = "v=spf1 " + " ".join(f"include:v{n}.test" for n in range(3)) + " -all"
        self.assertIn("SPF_TOO_MANY_VOID", self.spf(rec).codes())

    def test_macro_not_expanded(self):
        self.assertIn("SPF_MACRO", self.spf("v=spf1 include:%{d}.x.test -all").codes())

    def test_dns_error(self):
        s = e.check_spf("d.test", FakeResolver({("d.test", "TXT"): e.DNSError("SERVFAIL")}))
        self.assertEqual(s.codes(), ["DNS_ERROR"])


class DMARCTests(unittest.TestCase):
    def dmarc(self, record, domain="d.test", extra=None):
        data = {(f"_dmarc.{domain}", "TXT"): [record] if isinstance(record, str) else record}
        data.update(extra or {})
        return e.check_dmarc(domain, FakeResolver(data))

    def test_good(self):
        s = e.check_dmarc("example.com", FakeResolver(GOOD))
        self.assertIn("DMARC_P_REJECT", s.codes())
        self.assertFalse([f for f in s.findings if f.level in (e.HIGH, e.WARN)])

    def test_missing_multiple_version(self):
        self.assertIn("DMARC_MISSING", self.dmarc([]).codes())
        self.assertIn("DMARC_MULTIPLE", self.dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"]).codes())
        self.assertIn("DMARC_BAD_VERSION", self.dmarc("v=DMARC1 ;p=reject; v=DMARC1".replace(
            "v=DMARC1 ;", "v=dmarc1;")).codes())

    def test_policies(self):
        self.assertIn("DMARC_P_NONE", self.dmarc("v=DMARC1; p=none; rua=mailto:a@d.test").codes())
        self.assertIn("DMARC_BAD_POLICY", self.dmarc("v=DMARC1; p=block").codes())
        self.assertIn("DMARC_BAD_POLICY", self.dmarc("v=DMARC1; rua=mailto:a@d.test").codes())
        s = self.dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:a@d.test")
        self.assertIn("DMARC_WEAK_SUBPOLICY", s.codes())

    def test_pct_alignment_rua(self):
        self.assertIn("DMARC_PCT_PARTIAL", self.dmarc("v=DMARC1; p=reject; pct=20").codes())
        self.assertIn("DMARC_BAD_PCT", self.dmarc("v=DMARC1; p=reject; pct=abc").codes())
        self.assertIn("DMARC_BAD_ALIGNMENT", self.dmarc("v=DMARC1; p=reject; adkim=x").codes())
        self.assertIn("DMARC_NO_RUA", self.dmarc("v=DMARC1; p=reject").codes())
        self.assertIn("DMARC_BAD_URI", self.dmarc("v=DMARC1; p=reject; rua=a@d.test").codes())

    def test_external_rua_authorization(self):
        rec = "v=DMARC1; p=reject; rua=mailto:x@reports.test"
        self.assertIn("DMARC_RUA_UNAUTHORIZED", self.dmarc(rec).codes())
        ok = self.dmarc(rec, extra={("d.test._report._dmarc.reports.test", "TXT"): ["v=DMARC1"]})
        self.assertNotIn("DMARC_RUA_UNAUTHORIZED", ok.codes())

    def test_subdomain_inherits_org(self):
        r = FakeResolver({("_dmarc.example.com.cn", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com.cn"]})
        s = e.check_dmarc("mail.example.com.cn", r)
        self.assertIn("DMARC_INHERITED", s.codes())
        self.assertEqual(s.extra["policy"], "none")
        self.assertIn("DMARC_P_NONE", s.codes())

    def test_org_domain(self):
        self.assertEqual(e.org_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(e.org_domain("a.example.com"), "example.com")


class DKIMTests(unittest.TestCase):
    def one(self, record):
        sec = e.Section("DKIM")
        e.check_dkim_record("s", record, sec)
        return sec

    def test_key_sizes(self):
        self.assertEqual(e.rsa_key_bits(rsa_spki(2048)), 2048)
        self.assertIn("DKIM_KEY_OK", self.one(dkim(2048)).codes())
        self.assertIn("DKIM_1024_KEY", self.one(dkim(1024)).codes())
        self.assertIn("DKIM_WEAK_KEY", self.one(dkim(512)).codes())

    def test_pkcs1_key(self):
        n = (1 << 2047) | 1
        pkcs1 = tlv(0x30, tlv(0x02, b"\x00" + n.to_bytes(256, "big")) + tlv(0x02, b"\x01\x00\x01"))
        self.assertEqual(e.rsa_key_bits(pkcs1), 2048)

    def test_key_split_by_spaces(self):
        rec = dkim(2048)
        rec = rec[:60] + " " + rec[60:]   # TXT 分段拼接时常见的空格
        self.assertIn("DKIM_KEY_OK", self.one(rec).codes())

    def test_bad_records(self):
        self.assertIn("DKIM_REVOKED", self.one("v=DKIM1; p=").codes())
        self.assertIn("DKIM_BAD_KEY", self.one("v=DKIM1; p=@@@").codes())
        self.assertIn("DKIM_BAD_KEY", self.one("v=DKIM1; p=" + base64.b64encode(b"junk").decode()).codes())
        self.assertIn("DKIM_NO_KEY", self.one("v=DKIM1; k=rsa").codes())
        self.assertIn("DKIM_BAD_VERSION", self.one("k=rsa; v=DKIM1; p=").codes())

    def test_flags(self):
        self.assertIn("DKIM_TEST_MODE", self.one(dkim(2048, " t=y;")).codes())
        self.assertIn("DKIM_SHA1", self.one(dkim(2048, " h=sha1;")).codes())
        self.assertNotIn("DKIM_SHA1", self.one(dkim(2048, " h=sha1:sha256;")).codes())

    def test_ed25519(self):
        rec = "v=DKIM1; k=ed25519; p=" + base64.b64encode(b"\x01" * 32).decode()
        self.assertIn("DKIM_ED25519", self.one(rec).codes())

    def test_guess_and_explicit(self):
        s = e.check_dkim("example.com", FakeResolver(GOOD))
        self.assertEqual(s.extra["selectors_found"], ["selector1"])
        s = e.check_dkim("nothing.test", FakeResolver({}))
        self.assertEqual(s.codes(), ["DKIM_NOT_FOUND"])
        s = e.check_dkim("example.com", FakeResolver(GOOD), ["selector1", "missing"])
        self.assertIn("DKIM_SELECTOR_MISSING", s.codes())
        self.assertIn("DKIM_KEY_OK", s.codes())


class CLITests(unittest.TestCase):
    def run_cli(self, argv, data):
        buf = io.StringIO()
        with mock.patch.object(e, "make_resolver", return_value=FakeResolver(data)), \
                redirect_stdout(buf):
            code = e.main(argv)
        return code, buf.getvalue()

    def test_good_domain_exit_0(self):
        code, out = self.run_cli(["example.com"], GOOD)
        self.assertEqual(code, 0, out)
        self.assertIn("[DMARC]", out)

    def test_bad_domain_exit_1(self):
        code, out = self.run_cli(["you@bad.test"], {("bad.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(code, 1)
        self.assertIn("bad.test", out)
        self.assertIn("+all", out)

    def test_dns_error_exit_3(self):
        code, _ = self.run_cli(["x.test"], {("x.test", "MX"): e.DNSError("timeout")})
        self.assertEqual(code, 3)

    def test_json(self):
        code, out = self.run_cli(["example.com", "--json", "-s", "selector1"], GOOD)
        data = json.loads(out)
        self.assertEqual(data["domains"]["example.com"]["exit_code"], 0)
        self.assertEqual(code, 0)

    def test_mx_null_hint(self):
        code, out = self.run_cli(["parked.test"], {("parked.test", "MX"): ["0 ."]})
        self.assertIn("Null MX", out)
        self.assertIn("v=spf1 -all", out)

    def test_normalize(self):
        self.assertEqual(e.normalize_domain("https://Example.COM/path"), "example.com")
        self.assertEqual(e.normalize_domain("a@b.test."), "b.test")


if __name__ == "__main__":
    unittest.main()
