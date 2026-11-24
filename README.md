# Email Auth Checker

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that checks a domain's **SPF, DKIM and DMARC** DNS records (plus MX)
and points out the misconfigurations that let anyone **spoof email from your domain**, or
that send your real mail to spam.

It includes its own tiny **DNS client** built on `socket` (UDP, with TCP fallback when a
response is truncated), so it needs no `dnspython`. You can also switch to
**DNS-over-HTTPS** with `--doh`.

Standard library only: no `pip install`, no API key. Python 3.8+.

## Usage

```bash
python3 email_auth_check.py example.com                # check one domain
python3 email_auth_check.py you@example.com            # pasting an email address works too
python3 email_auth_check.py example.com -s google      # DKIM selector(s) to check (repeat or comma-separate)
python3 email_auth_check.py example.com -v             # also show passed checks + the SPF lookup tree
python3 email_auth_check.py example.com --json         # machine-readable output
python3 email_auth_check.py example.com --dns 8.8.8.8  # pick a DNS server (default: /etc/resolv.conf)
python3 email_auth_check.py example.com --doh          # DNS-over-HTTPS (Cloudflare by default)
python3 email_auth_check.py a.com b.com c.com          # several domains

python3 -m unittest -v                                 # offline tests (fake DNS, no network)
```

Example output (the CLI prints in Chinese):

```
📧 example.com   (DNS: 192.168.1.1)

[MX]
  记录: 10 mx.example.com
  ✅ 1 条 MX 记录

[SPF]
  记录: v=spf1 include:_spf.example.net ptr ?all
  ⚠️  ptr 机制已被 RFC 7208 弃用：慢、不可靠，部分接收方直接忽略
  ⚠️  "?all" 是中立：不在名单里的服务器也不会被判失败

[DMARC]
  记录: v=DMARC1; p=none; rua=mailto:x@vendor.test
  ⚠️  策略 p=none 只监控不拦截，伪造邮件照样投递。…
  ⚠️  rua 发往外部域名 vendor.test，但 example.com._report._dmarc.vendor.test 没有授权记录，报告会被丢弃

[DKIM]
  记录: selector1: v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ…
  ⚠️  [selector1] RSA 1024 位：仍被接受但已不推荐，建议轮换为 2048 位
  ⚠️  [selector1] t=y 测试模式：接收方会把签名失败当作没签名

总结: 警告 6
```

(`记录` = record, `高危` = high, `警告` = warning, `提示` = info, `总结` = summary.)

| Exit code | Meaning |
|---|---|
| `0` | No high-severity issues or warnings |
| `1` | Issues found |
| `2` | Invalid domain |
| `3` | DNS query failed (timeout, SERVFAIL…) |

## The three records in one minute

```
            "From: boss@example.com"
                     │
     ┌───────────────┼──────────────────┐
     ▼               ▼                  ▼
   SPF             DKIM               DMARC
 "Which servers   "Is this message    "If SPF/DKIM fail (or don't match
  may send for     signed with a key   the From: domain), what should the
  example.com?"    published in DNS?"  receiver do? Where to send reports?"
 TXT @ example.com TXT @ <selector>.   TXT @ _dmarc.example.com
                   _domainkey.example.com
```

SPF and DKIM on their own **don't protect the visible `From:` address**: SPF checks the
hidden envelope sender, and DKIM proves *some* domain signed the mail. DMARC ties them to
the `From:` domain and tells receivers to reject failures. That's why a domain with SPF
and DKIM but no DMARC (or `p=none`) can still be spoofed.

## What it checks

**MX**
- No MX / Null MX (`0 .`): the domain doesn't receive mail. Parked domains still need
  `v=spf1 -all` + `p=reject`, or attackers spoof them precisely *because* nobody watches.

**SPF** (RFC 7208)
- Missing, or more than one `v=spf1` record (multiple = `permerror`, SPF is ignored)
- `+all` (anyone may send), `?all` (neutral), missing `all`, `all` not last; `~all` is noted
- Unknown mechanisms (typos like `inclde:`), invalid `ip4:`/`ip6:`, huge ranges (`ip4:0.0.0.0/0`)
- Deprecated `ptr`
- **The 10-DNS-lookup limit**: it walks the whole `include:` / `redirect=` tree and counts
  `include`, `a`, `mx`, `ptr`, `exists`, `redirect`. Over 10 means `permerror` for *every*
  message, which is the most common real-world SPF bug when people stack SaaS includes.
  `-v` prints the tree.
- Includes that point to a domain with no SPF, include loops, more than 2 void lookups

**DMARC** (RFC 7489)
- Missing (for subdomains it falls back to the organizational domain, then uses `sp=`)
- Multiple records, `v=DMARC1` not first, missing/invalid `p=`
- `p=none` (monitoring only), `sp=` / `np=` weaker than `p=`, `pct` < 100
- No `rua` (you get no reports), non-`mailto:` URIs
- **External report authorization**: if `rua` sends reports to another domain, that domain
  must publish `example.com._report._dmarc.<their-domain>`, or reports are silently dropped.
  The tool queries it.
- Invalid `adkim`/`aspf`, unknown tags, `ruf` notes

**DKIM** (RFC 6376, RFC 8301, RFC 8463)
- Selectors can't be listed via DNS, so the tool tries ~35 common ones (`google`,
  `selector1`, `k1`, `default`, …) unless you pass `-s`. The real one is the `s=` value in
  the `DKIM-Signature:` header of a mail you sent.
- **RSA key size**: it Base64-decodes `p=` and parses the DER `SubjectPublicKeyInfo` with
  a tiny ASN.1 reader to get the modulus length. < 1024 bits = high (must be rejected per
  RFC 8301, and 512-bit keys have been factored for spoofing), 1024 = warning, ≥ 2048 = ok.
  Ed25519 keys are recognised.
- Empty `p=` (revoked key), broken Base64, `t=y` (test mode), `h=sha1` only

## How the DNS client works

```
build_query()   header (ID, RD flag) + QNAME labels + QTYPE + EDNS0 OPT (4096-byte UDP)
      │  UDP :53
      ▼
parse_response() check ID → header flags → skip question → read answers
                 (follows name-compression pointers, with a loop guard)
      │  TC=1 (truncated)?  → resend over TCP with a 2-byte length prefix
      ▼
TXT rdata = <len><bytes><len><bytes>…  → concatenated (long DKIM keys span many 255-byte strings)
NXDOMAIN → "no record";   SERVFAIL / REFUSED / timeout → DNSError (exit 3)
```

CNAMEs (common for DKIM when an email provider hosts your key) are followed by the
recursive resolver; the client only keeps answers of the type it asked for.

## Limitations

- **DKIM can't be proven absent.** "No DKIM found" only means none of the guessed
  selectors exist. Use `-s`.
- **This checks DNS, not mail flow.** Whether your servers actually sign mail, or whether
  all your senders are in SPF, only shows up in DMARC aggregate reports (that's what `rua` is for).
- The organizational domain is approximated (last two labels, plus a short list like
  `com.cn`, `co.uk`) instead of the full Public Suffix List.
- SPF macros (`%{d}`) aren't expanded, and the per-`mx` 10-address sub-limit isn't counted.
- Plain UDP DNS isn't authenticated (no DNSSEC validation). Use `--doh` on networks you don't trust.
- Not covered: MTA-STS, TLS-RPT, BIMI, DNSSEC.

## Real-world equivalents

[MXToolbox](https://mxtoolbox.com/), [dmarcian](https://dmarcian.com/domain-checker/),
[Google Admin Toolbox CheckMX](https://toolbox.googleapps.com/apps/checkmx/),
[learndmarc.com](https://www.learndmarc.com/) (great visual walkthrough), and for
reports: Postmark DMARC, Valimail, EasyDMARC.
