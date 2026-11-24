#!/usr/bin/env python3
"""
邮件域名配置检查器 (Email Auth Checker)

检查一个域名的 SPF、DKIM、DMARC（以及 MX）DNS 记录，
指出会让别人轻松伪造你域名发信、或让正常邮件进垃圾箱的配置错误。

DNS 查询自己实现：用 socket 拼 DNS 报文走 UDP（被截断时自动改 TCP），
也可以用 --doh 改走 DNS-over-HTTPS。只依赖 Python 标准库，Python 3.8+。
"""

import argparse
import base64
import binascii
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------- DNS 客户端

TYPE_A, TYPE_MX, TYPE_TXT, TYPE_AAAA, TYPE_OPT = 1, 15, 16, 28, 41
TYPE_NAMES = {"A": TYPE_A, "MX": TYPE_MX, "TXT": TYPE_TXT, "AAAA": TYPE_AAAA}
FALLBACK_DNS = "1.1.1.1"
USER_AGENT = "email-auth-checker-learning-project"


class DNSError(Exception):
    """查询失败（超时、SERVFAIL、REFUSED、报文损坏等）。NXDOMAIN 不算失败。"""


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        try:
            raw = label.encode("idna") if label else b""
        except UnicodeError:
            raw = b""
        if not raw or len(raw) > 63:
            raise DNSError(f"非法域名: {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, qid: int) -> bytes:
    # 头部: ID, 标志 0x0100 (RD=请求递归), 1 个问题, 0 应答, 0 授权, 1 附加 (EDNS0)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    # EDNS0 OPT 伪记录：告诉服务器我们能收 4096 字节的 UDP 响应，减少截断
    opt = b"\x00" + struct.pack(">HHIH", TYPE_OPT, 4096, 0, 0)
    return header + question + opt


def read_name(msg: bytes, pos: int) -> tuple:
    """解析可能带压缩指针的域名，返回 (名字, 名字之后的位置)。"""
    labels, jumps, end = [], 0, None
    while True:
        if pos >= len(msg):
            raise DNSError("响应报文被截断")
        length = msg[pos]
        if length & 0xC0 == 0xC0:  # 压缩指针：跳到报文前面某处继续读
            if pos + 1 >= len(msg):
                raise DNSError("响应报文被截断")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            jumps += 1
            if jumps > 20:
                raise DNSError("域名压缩指针成环")
            continue
        if length == 0:
            return ".".join(labels), (end if end is not None else pos + 1)
        labels.append(msg[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length


def parse_response(msg: bytes, qid: int, qtype: int) -> dict:
    """返回 {"rcode", "tc", "answers"}；answers 只保留类型等于 qtype 的记录。"""
    if len(msg) < 12:
        raise DNSError("响应太短")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise DNSError("响应 ID 不匹配")
    pos = 12
    for _ in range(qd):
        _, pos = read_name(msg, pos)
        pos += 4
    answers = []
    for _ in range(an):
        _, pos = read_name(msg, pos)
        if pos + 10 > len(msg):
            raise DNSError("响应报文被截断")
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        rdata = msg[pos:pos + rdlen]
        if rtype == qtype:  # CNAME 等中间记录跳过，递归服务器已经帮我们跟过了
            answers.append(decode_rdata(msg, pos, rtype, rdata))
        pos += rdlen
    return {"rcode": flags & 0x000F, "tc": bool(flags & 0x0200), "answers": answers}


def decode_rdata(msg: bytes, pos: int, rtype: int, rdata: bytes) -> str:
    if rtype == TYPE_TXT:
        # TXT = 若干个 <长度字节><内容>，单段最长 255，长记录要拼起来
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n])
            i += 1 + n
        return b"".join(parts).decode("utf-8", "replace")
    if rtype == TYPE_MX:
        pref = struct.unpack(">H", rdata[:2])[0]
        host, _ = read_name(msg, pos + 2)
        return f"{pref} {host or '.'}"
    if rtype == TYPE_A:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if rtype == TYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    return rdata.hex()


class UDPResolver:
    """最小 DNS 客户端：UDP 查询，响应被截断 (TC=1) 时改用 TCP。"""

    def __init__(self, server: str, timeout: float = 3.0, retries: int = 2):
        self.server = server.split("%")[0]
        self.family = socket.AF_INET6 if ":" in self.server else socket.AF_INET
        self.timeout, self.retries = timeout, retries
        self.label = self.server

    def query(self, name: str, rtype: str) -> List[str]:
        qtype = TYPE_NAMES[rtype]
        last_err: Exception = DNSError("未知错误")
        for _ in range(self.retries + 1):
            qid = random.randint(0, 0xFFFF)
            packet = build_query(name, qtype, qid)
            try:
                resp = parse_response(self._udp(packet), qid, qtype)
                if resp["tc"]:
                    resp = parse_response(self._tcp(packet), qid, qtype)
                return self._result(name, rtype, resp["rcode"], resp["answers"])
            except (socket.timeout, OSError) as e:
                last_err = e
        raise DNSError(f"{name} {rtype} 查询失败: {last_err}")

    @staticmethod
    def _result(name, rtype, rcode, answers):
        if rcode == 3:  # NXDOMAIN：域名不存在 → 当作“没有记录”
            return []
        if rcode != 0:
            names = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}
            raise DNSError(f"{name} {rtype} 查询失败: {names.get(rcode, rcode)}")
        return answers

    def _udp(self, packet: bytes) -> bytes:
        with socket.socket(self.family, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (self.server, 53))
            return s.recv(65535)

    def _tcp(self, packet: bytes) -> bytes:
        with socket.create_connection((self.server, 53), timeout=self.timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            buf = b""
            while len(buf) < 2 or len(buf) < 2 + struct.unpack(">H", buf[:2])[0]:
                chunk = s.recv(65535)
                if not chunk:
                    raise DNSError("TCP 连接提前关闭")
                buf += chunk
            return buf[2:2 + struct.unpack(">H", buf[:2])[0]]


def parse_doh_txt(data: str) -> str:
    """DoH JSON 里的 TXT 可能是 '"part1" "part2"'（带引号、可能有转义），也可能不带引号。"""
    if not data.startswith('"'):
        return data
    out = []
    for chunk in re.findall(r'"((?:[^"\\]|\\.)*)"', data):
        chunk = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), chunk)
        out.append(re.sub(r"\\(.)", r"\1", chunk))
    return "".join(out)


class DoHResolver:
    """DNS-over-HTTPS（JSON 格式，Cloudflare / Google / AliDNS 都支持）。"""

    def __init__(self, url: str, timeout: float = 8.0):
        self.url, self.timeout, self.label = url, timeout, url

    def query(self, name: str, rtype: str) -> List[str]:
        qs = urllib.parse.urlencode({"name": name, "type": TYPE_NAMES[rtype]})  # 数字类型，各家都认
        sep = "&" if "?" in self.url else "?"
        req = urllib.request.Request(f"{self.url}{sep}{qs}", headers={
            "Accept": "application/dns-json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (OSError, ValueError) as e:
            raise DNSError(f"{name} {rtype} DoH 查询失败: {e}") from e
        answers = [a.get("data", "") for a in body.get("Answer", [])
                   if a.get("type") == TYPE_NAMES[rtype]]
        if rtype == "TXT":
            answers = [parse_doh_txt(a) for a in answers]
        if rtype == "MX":
            answers = [a if a.endswith(" .") else a.rstrip(".") for a in answers]
        return UDPResolver._result(name, rtype, body.get("Status", 2), answers)


def system_nameserver(path: str = "/etc/resolv.conf") -> Optional[str]:
    """读系统 DNS（macOS / Linux 都有 /etc/resolv.conf），读不到返回 None。"""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return None


# ---------------------------------------------------------------- 检查结果

HIGH, WARN, INFO, OK, ERROR = "high", "warn", "info", "ok", "error"
LEVEL_ICON = {HIGH: "❌", WARN: "⚠️ ", INFO: "ℹ️ ", OK: "✅", ERROR: "💥"}
LEVEL_NAME = {HIGH: "高危", WARN: "警告", INFO: "提示", OK: "通过", ERROR: "查询失败"}


@dataclass
class Finding:
    level: str
    code: str
    message: str


@dataclass
class Section:
    name: str
    records: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    extra: Dict[str, object] = field(default_factory=dict)

    def add(self, level: str, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))

    def codes(self) -> List[str]:
        return [f.code for f in self.findings]


def txt_records(resolver, name: str, prefix: str) -> List[str]:
    """取 name 的 TXT 记录，只保留以 prefix 开头（忽略大小写）的。"""
    p = prefix.lower()
    return [t.strip() for t in resolver.query(name, "TXT")
            if t.strip().lower() == p or t.strip().lower().startswith(p + " ")
            or t.strip().lower().startswith(p + ";")]


# ---------------------------------------------------------------- MX

def check_mx(domain: str, resolver) -> Section:
    sec = Section("MX")
    try:
        mx = resolver.query(domain, "MX")
    except DNSError as e:
        sec.add(ERROR, "DNS_ERROR", str(e))
        return sec
    sec.records = sorted(mx, key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 0)
    null_mx = any(r.split()[-1] in (".", "") for r in mx)
    sec.extra["receives_mail"] = bool(mx) and not null_mx
    if null_mx:
        sec.add(INFO, "MX_NULL", "Null MX（RFC 7505）：域名声明自己不收邮件。"
                "如果也不发信，SPF 应为 \"v=spf1 -all\"，DMARC 应为 p=reject。")
    elif not mx:
        sec.add(INFO, "MX_NONE", "没有 MX 记录：这个域名不收邮件。"
                "不发信的域名也要防伪造：SPF \"v=spf1 -all\" + DMARC p=reject。")
    else:
        sec.add(OK, "MX_OK", f"{len(mx)} 条 MX 记录")
    return sec


# ---------------------------------------------------------------- SPF

SPF_LOOKUP_LIMIT = 10     # RFC 7208 4.6.4：整棵 include 树最多 10 次 DNS 查询
SPF_VOID_LIMIT = 2        # RFC 7208 4.6.4：最多 2 次“空查询”
SPF_LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}
SPF_MECHS = SPF_LOOKUP_MECHS | {"all", "ip4", "ip6"}


def parse_spf_terms(record: str) -> List[dict]:
    """把 'v=spf1 ...' 拆成 term 列表：{"raw", "qualifier", "name", "value", "modifier"}。"""
    terms = []
    for raw in record.split()[1:]:
        m = re.fullmatch(r"([a-zA-Z][\w.-]*)=(.*)", raw)
        if m:
            terms.append({"raw": raw, "qualifier": "", "name": m.group(1).lower(),
                          "value": m.group(2), "modifier": True})
            continue
        qualifier = raw[0] if raw[0] in "+-~?" else "+"
        body = raw[1:] if raw[0] in "+-~?" else raw
        m = re.match(r"([^:/]*)([:/]?)(.*)", body)
        name, sep, value = m.group(1), m.group(2), m.group(3)
        if sep == "/":       # a/24、mx/24 这种只有前缀长度没有域名
            value = "/" + value
        terms.append({"raw": raw, "qualifier": qualifier, "name": name.lower(),
                      "value": value, "modifier": False})
    return terms


def _spf_target(term: dict) -> str:
    return term["value"].split("/")[0] if term["value"] and not term["value"].startswith("/") else ""


def count_spf_lookups(domain: str, resolver, sec: Section, state: dict, depth: int = 0) -> None:
    """递归统计 include / redirect 树里一共会触发多少次 DNS 查询。"""
    if domain.lower() in state["stack"]:
        sec.add(HIGH, "SPF_LOOP", f"include/redirect 出现循环：{' → '.join(state['stack'] + [domain])}")
        return
    if depth > 0:
        try:
            records = txt_records(resolver, domain, "v=spf1")
        except DNSError as e:
            sec.add(ERROR, "DNS_ERROR", str(e))
            return
        if not records:
            state["void"] += 1
            sec.add(HIGH, "SPF_INCLUDE_MISSING",
                    f"引用的 {domain} 没有 SPF 记录，接收方会判定 permerror（SPF 整体失效）")
            return
        if len(records) > 1:
            sec.add(HIGH, "SPF_INCLUDE_MULTIPLE", f"引用的 {domain} 有多条 SPF 记录 → permerror")
        record = records[0]
    else:
        record = state["root_record"]
    state["stack"].append(domain.lower())
    terms = parse_spf_terms(record)
    has_all = any(t["name"] == "all" and not t["modifier"] for t in terms)
    for t in terms:
        if t["modifier"] and t["name"] == "redirect" and has_all:
            continue  # 有 all 时 redirect 会被忽略
        if t["modifier"] and t["name"] != "redirect":
            continue
        if not t["modifier"] and t["name"] not in SPF_LOOKUP_MECHS:
            continue
        state["count"] += 1
        state["tree"].append(("  " * depth) + t["raw"] + (f"  ({domain})" if depth else ""))
        if t["name"] in ("include", "redirect"):
            target = t["value"] if t["modifier"] else _spf_target(t)
            if "%" in target:
                sec.add(INFO, "SPF_MACRO", f"{t['raw']} 使用了宏，无法离线展开，查询次数可能偏少")
            elif target and state["count"] <= SPF_LOOKUP_LIMIT + 5:  # 远超上限就不再往下查了
                count_spf_lookups(target, resolver, sec, state, depth + 1)
    state["stack"].pop()


def check_spf(domain: str, resolver, receives_mail: Optional[bool] = None) -> Section:
    sec = Section("SPF")
    try:
        records = txt_records(resolver, domain, "v=spf1")
    except DNSError as e:
        sec.add(ERROR, "DNS_ERROR", str(e))
        return sec
    sec.records = records
    if not records:
        hint = ("（不发信的域名建议发布 \"v=spf1 -all\"）" if receives_mail is False else
                "，任何人都能冒充这个域名发信而不会被 SPF 拦截")
        sec.add(HIGH, "SPF_MISSING", "没有 SPF 记录" + hint)
        return sec
    if len(records) > 1:
        sec.add(HIGH, "SPF_MULTIPLE", f"有 {len(records)} 条 SPF 记录，RFC 规定这会直接 permerror。"
                "请合并成一条")
    record = records[0]
    terms = parse_spf_terms(record)
    sec.add(OK, "SPF_FOUND", "找到 SPF 记录")

    # 1) 语法：未知机制 / 非法 IP / 过宽网段 / ptr
    for t in terms:
        if t["modifier"]:
            if t["name"] not in ("redirect", "exp"):
                sec.add(INFO, "SPF_UNKNOWN_MODIFIER", f"未知修饰符 {t['raw']}（会被忽略）")
            continue
        if t["name"] not in SPF_MECHS:
            sec.add(HIGH, "SPF_SYNTAX", f"无法识别的机制 {t['raw']!r} → permerror。拼写错误？")
        elif t["name"] in ("ip4", "ip6"):
            try:
                net = ipaddress.ip_network(t["value"], strict=False)
            except ValueError:
                sec.add(HIGH, "SPF_BAD_IP", f"{t['raw']} 不是合法的 IP/网段 → permerror")
                continue
            if t["qualifier"] in "+":
                wide = 8 if net.version == 4 else 16
                broad = 16 if net.version == 4 else 32
                if net.prefixlen <= wide:
                    sec.add(HIGH, "SPF_BROAD_IP", f"{t['raw']} 放行了 {net.num_addresses:,} 个地址，"
                            "几乎等于谁都能发")
                elif net.prefixlen < broad:
                    sec.add(WARN, "SPF_BROAD_IP", f"{t['raw']} 网段很大（/{net.prefixlen}），确认真的都是你的发信服务器")
        elif t["name"] == "ptr":
            sec.add(WARN, "SPF_PTR", "ptr 机制已被 RFC 7208 弃用：慢、不可靠，部分接收方直接忽略")

    # 2) all 的限定符：决定“不在名单里的服务器”怎么处理
    alls = [i for i, t in enumerate(terms) if t["name"] == "all" and not t["modifier"]]
    has_redirect = any(t["modifier"] and t["name"] == "redirect" for t in terms)
    if alls:
        q = terms[alls[0]]["qualifier"]
        if q == "+":
            sec.add(HIGH, "SPF_PASS_ALL", "\"+all\" 等于允许全世界任何服务器代表你发信，SPF 形同虚设")
        elif q == "?":
            sec.add(WARN, "SPF_NEUTRAL_ALL", "\"?all\" 是中立：不在名单里的服务器也不会被判失败")
        elif q == "~":
            sec.add(INFO, "SPF_SOFTFAIL_ALL", "\"~all\"（软失败）：配合 DMARC 足够；"
                    "确认所有发信源都列全后可以改成 \"-all\"")
        else:
            sec.add(OK, "SPF_FAIL_ALL", "\"-all\"：不在名单里的服务器一律判失败")
        if alls[0] != len([t for t in terms if not t["modifier"]]) - 1:
            sec.add(WARN, "SPF_ALL_NOT_LAST", "all 后面还有机制，它们永远不会被匹配到")
    elif not has_redirect:
        sec.add(WARN, "SPF_NO_ALL", "记录没有以 all 结尾，默认结果是中立（?all），伪造邮件不会被判失败")

    # 3) DNS 查询次数（include 树）
    state = {"count": 0, "void": 0, "stack": [], "tree": [], "root_record": record}
    count_spf_lookups(domain, resolver, sec, state)
    sec.extra["lookups"] = state["count"]
    sec.extra["lookup_tree"] = state["tree"]
    n = state["count"]
    if n > SPF_LOOKUP_LIMIT:
        sec.add(HIGH, "SPF_TOO_MANY_LOOKUPS", f"需要 {n} 次 DNS 查询，超过上限 {SPF_LOOKUP_LIMIT} → "
                "permerror，SPF 对所有邮件都失效。减少 include，或把 IP 直接写成 ip4/ip6")
    elif n >= SPF_LOOKUP_LIMIT - 2:
        sec.add(WARN, "SPF_LOOKUPS_NEAR_LIMIT", f"需要 {n}/{SPF_LOOKUP_LIMIT} 次 DNS 查询，接近上限；"
                "第三方服务商一改 include 就可能超标")
    else:
        sec.add(OK, "SPF_LOOKUPS_OK", f"DNS 查询次数 {n}/{SPF_LOOKUP_LIMIT}")
    if state["void"] > SPF_VOID_LIMIT:
        sec.add(HIGH, "SPF_TOO_MANY_VOID", f"{state['void']} 次空查询，超过上限 {SPF_VOID_LIMIT}")
    return sec


# ---------------------------------------------------------------- DMARC

# 常见的“两段式”公共后缀，用来粗略推算组织域（完整做法要用 Public Suffix List）
MULTI_PART_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "com.hk", "com.tw", "com.sg",
    "co.nz", "com.br", "co.kr", "co.in", "co.za", "com.mx",
}


def org_domain(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    n = 3 if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 2
    return ".".join(labels[-n:])


def parse_tags(record: str) -> List[tuple]:
    """'k1=v1; k2=v2' → [(k1, v1), (k2, v2)]（DMARC 和 DKIM 都用这种格式）。"""
    tags = []
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags.append((k.strip().lower(), re.sub(r"\s+", "", v) if k.strip().lower() == "p"
                         else v.strip()))
    return tags


DMARC_TAGS = {"v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri", "t", "psd"}


def check_dmarc(domain: str, resolver) -> Section:
    sec = Section("DMARC")
    name = f"_dmarc.{domain}"
    try:
        records = txt_records(resolver, name, "v=DMARC1")
        inherited = False
        org = org_domain(domain)
        if not records and org != domain.lower():
            records = txt_records(resolver, f"_dmarc.{org}", "v=DMARC1")
            inherited = bool(records)
    except DNSError as e:
        sec.add(ERROR, "DNS_ERROR", str(e))
        return sec
    sec.records = records
    if not records:
        sec.add(HIGH, "DMARC_MISSING", f"{name} 没有 DMARC 记录：接收方不知道 SPF/DKIM 失败时该怎么处理，"
                "也不会给你发报告。起步可以用 \"v=DMARC1; p=none; rua=mailto:你的邮箱\"")
        return sec
    if len(records) > 1:
        sec.add(HIGH, "DMARC_MULTIPLE", f"有 {len(records)} 条 DMARC 记录，接收方会当作没有 DMARC")
    if inherited:
        sec.add(INFO, "DMARC_INHERITED", f"{domain} 自己没有记录，继承组织域 {org} 的 DMARC（看 sp=）")
    record = records[0]
    tags = parse_tags(record)
    t = dict(tags)
    sec.add(OK, "DMARC_FOUND", "找到 DMARC 记录")
    if not tags or tags[0] != ("v", "DMARC1"):
        sec.add(HIGH, "DMARC_BAD_VERSION", "第一个标签必须正好是 v=DMARC1（区分大小写）")

    p = t.get("p", "").lower()
    if inherited and "sp" in t:
        p = t["sp"].lower()
    if p not in ("none", "quarantine", "reject"):
        sec.add(HIGH, "DMARC_BAD_POLICY", f"p={t.get('p', '(缺失)')} 无效，必须是 none / quarantine / reject")
    elif p == "none":
        sec.add(WARN, "DMARC_P_NONE", "策略 p=none 只监控不拦截，伪造邮件照样投递。"
                "看完报告确认正常邮件都通过后，逐步改成 quarantine → reject")
    elif p == "quarantine":
        sec.add(OK, "DMARC_P_QUARANTINE", "策略 quarantine：未通过的邮件进垃圾箱（最终目标可以是 reject）")
    else:
        sec.add(OK, "DMARC_P_REJECT", "策略 reject：未通过的邮件直接拒收")
    sec.extra["policy"] = p

    strength = {"none": 0, "quarantine": 1, "reject": 2}
    for tag, label in (("sp", "子域名"), ("np", "不存在的子域名")):
        if tag in t and not inherited:
            v = t[tag].lower()
            if v not in strength:
                sec.add(WARN, "DMARC_BAD_SUBPOLICY", f"{tag}={t[tag]} 无效")
            elif p in strength and strength[v] < strength[p]:
                sec.add(WARN, "DMARC_WEAK_SUBPOLICY", f"{tag}={v} 比主策略弱，攻击者可以用"
                        f"{label}（如 xxx.{domain}）伪造")

    if "pct" in t:
        try:
            pct = int(t["pct"])
        except ValueError:
            pct = -1
        if not 0 <= pct <= 100:
            sec.add(WARN, "DMARC_BAD_PCT", f"pct={t['pct']} 无效（0-100）")
        elif pct < 100 and p != "none":
            sec.add(WARN, "DMARC_PCT_PARTIAL", f"pct={pct}：只有 {pct}% 的失败邮件会执行策略，其余放行")

    for tag in ("adkim", "aspf"):
        if tag in t and t[tag].lower() not in ("r", "s"):
            sec.add(WARN, "DMARC_BAD_ALIGNMENT", f"{tag}={t[tag]} 无效（只能是 r 或 s）")

    if "rua" not in t:
        sec.add(WARN, "DMARC_NO_RUA", "没有 rua：收不到聚合报告，就没法知道谁在用你的域名发信、"
                "改 reject 前也无法确认正常邮件都通过")
    else:
        check_report_uris(domain if not inherited else org, "rua", t["rua"], resolver, sec)
    if "ruf" in t:
        sec.add(INFO, "DMARC_RUF", "设置了 ruf（失败样本报告）：大多数邮箱服务商不再发送，且可能含邮件内容")
        check_report_uris(domain if not inherited else org, "ruf", t["ruf"], resolver, sec)

    unknown = [k for k, _ in tags if k not in DMARC_TAGS]
    if unknown:
        sec.add(INFO, "DMARC_UNKNOWN_TAG", f"未知标签 {', '.join(unknown)}（会被忽略）")
    return sec


def check_report_uris(domain: str, tag: str, value: str, resolver, sec: Section) -> None:
    for uri in [u.strip() for u in value.split(",") if u.strip()]:
        if not uri.lower().startswith("mailto:") or "@" not in uri:
            sec.add(WARN, "DMARC_BAD_URI", f"{tag} 里的 {uri!r} 不是 mailto: 地址")
            continue
        dest = uri.split("@", 1)[1].split("!")[0].lower().rstrip(".")
        if org_domain(dest) == org_domain(domain):
            continue
        # 报告发往别的域名时，那个域名必须发布授权记录（RFC 7489 7.1），否则报告会被丢弃
        auth = f"{domain}._report._dmarc.{dest}"
        try:
            ok = txt_records(resolver, auth, "v=DMARC1")
        except DNSError as e:
            sec.add(ERROR, "DNS_ERROR", str(e))
            continue
        if not ok:
            sec.add(WARN, "DMARC_RUA_UNAUTHORIZED", f"{tag} 发往外部域名 {dest}，但 {auth} 没有授权记录，"
                    "报告会被丢弃")


# ---------------------------------------------------------------- DKIM

# DKIM 的选择器 (selector) 无法通过 DNS 枚举，只能猜常见的；最准的是看邮件头 DKIM-Signature 的 s=
COMMON_SELECTORS = [
    "default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "k3",
    "s1", "s2", "smtp", "email", "mx", "key1", "key2", "dk", "mandrill", "mxvault",
    "everlytic", "zoho", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
    "sig1", "litesrv", "pm", "amazonses", "turbo-smtp", "hs1", "hs2", "aliyun-cn-hangzhou",
]


def _der_read(data: bytes, pos: int) -> tuple:
    """读一个 DER TLV，返回 (tag, value, 下一个位置)。"""
    if pos + 2 > len(data):
        raise ValueError("DER 截断")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("DER 长度非法")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("DER 截断")
    return tag, data[pos:pos + length], pos + length


def rsa_key_bits(der: bytes) -> int:
    """从 SubjectPublicKeyInfo（或裸 PKCS#1 RSAPublicKey）里取出 RSA 模数位数。"""
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError("不是 DER SEQUENCE")
    first_tag, first, nxt = _der_read(body, 0)
    if first_tag == 0x02:                    # PKCS#1: SEQUENCE { INTEGER n, INTEGER e }
        return int.from_bytes(first, "big").bit_length()
    if first_tag != 0x30:                    # SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        raise ValueError("无法识别的公钥结构")
    bit_tag, bits, _ = _der_read(body, nxt)
    if bit_tag != 0x03 or not bits:
        raise ValueError("缺少 BIT STRING")
    return rsa_key_bits(bits[1:])            # 第一个字节是“未使用位数”，跳过


def check_dkim_record(selector: str, record: str, sec: Section) -> None:
    where = f"[{selector}]"
    tags = parse_tags(record)
    t = dict(tags)
    if "v" in t and (tags[0][0] != "v" or t["v"] != "DKIM1"):
        sec.add(HIGH, "DKIM_BAD_VERSION", f"{where} v= 必须是第一个标签且等于 DKIM1")
    if "p" not in t:
        sec.add(HIGH, "DKIM_NO_KEY", f"{where} 没有 p= 公钥标签")
        return
    if t["p"] == "":
        sec.add(WARN, "DKIM_REVOKED", f"{where} p= 为空：这个密钥已被吊销。如果还在用它签名，验证会失败")
        return
    k = t.get("k", "rsa").lower()
    try:
        key = base64.b64decode(t["p"], validate=True)
    except (binascii.Error, ValueError):
        sec.add(HIGH, "DKIM_BAD_KEY", f"{where} p= 不是合法的 Base64（常见原因：复制时断行或少了字符）")
        return
    if k == "ed25519":
        if len(key) == 32:
            sec.add(OK, "DKIM_ED25519", f"{where} Ed25519 密钥")
        else:
            sec.add(HIGH, "DKIM_BAD_KEY", f"{where} Ed25519 公钥应为 32 字节，实际 {len(key)}")
    elif k == "rsa":
        try:
            bits = rsa_key_bits(key)
        except ValueError as e:
            sec.add(HIGH, "DKIM_BAD_KEY", f"{where} 无法解析 RSA 公钥：{e}")
            return
        sec.extra.setdefault("key_bits", {})[selector] = bits
        if bits < 1024:
            sec.add(HIGH, "DKIM_WEAK_KEY", f"{where} RSA {bits} 位：可被分解伪造签名，"
                    "且 RFC 8301 要求接收方拒绝。请换成 2048 位")
        elif bits < 2048:
            sec.add(WARN, "DKIM_1024_KEY", f"{where} RSA {bits} 位：仍被接受但已不推荐，建议轮换为 2048 位")
        else:
            sec.add(OK, "DKIM_KEY_OK", f"{where} RSA {bits} 位")
    else:
        sec.add(WARN, "DKIM_UNKNOWN_KEYTYPE", f"{where} 未知密钥类型 k={k}")
    if "h" in t and all(h.strip().lower() == "sha1" for h in t["h"].split(":")):
        sec.add(WARN, "DKIM_SHA1", f"{where} h=sha1：只允许 SHA-1，RFC 8301 已禁止，应允许 sha256")
    flags = [f.strip().lower() for f in t.get("t", "").split(":") if f.strip()]
    if "y" in flags:
        sec.add(WARN, "DKIM_TEST_MODE", f"{where} t=y 测试模式：接收方会把签名失败当作没签名")


def check_dkim(domain: str, resolver, selectors: Optional[List[str]] = None) -> Section:
    sec = Section("DKIM")
    guessing = not selectors
    selectors = selectors or COMMON_SELECTORS

    def lookup(sel):
        try:
            return sel, [r for r in resolver.query(f"{sel}._domainkey.{domain}", "TXT")
                         if "p=" in r.replace(" ", "") or r.strip().startswith("v=DKIM1")], None
        except DNSError as e:
            return sel, [], e

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lookup, selectors))
    found = []
    for sel, records, err in results:
        if err and not guessing:
            sec.add(ERROR, "DNS_ERROR", str(err))
        elif records:
            found.append(sel)
            sec.records.append(f"{sel}: {records[0][:80]}{'…' if len(records[0]) > 80 else ''}")
            check_dkim_record(sel, records[0], sec)
        elif not guessing:
            sec.add(HIGH, "DKIM_SELECTOR_MISSING", f"[{sel}] {sel}._domainkey.{domain} 没有 DKIM 记录")
    sec.extra["selectors_found"] = found
    if guessing and not found:
        sec.add(INFO, "DKIM_NOT_FOUND", f"试了 {len(selectors)} 个常见选择器都没找到。"
                "DKIM 选择器无法枚举，请从你发出的邮件头 DKIM-Signature 里找 s=xxx，再用 -s xxx 指定")
    return sec


# ---------------------------------------------------------------- 汇总与输出

def check_domain(domain: str, resolver, selectors: Optional[List[str]] = None) -> List[Section]:
    mx = check_mx(domain, resolver)
    return [mx, check_spf(domain, resolver, mx.extra.get("receives_mail")),
            check_dmarc(domain, resolver), check_dkim(domain, resolver, selectors)]


def count_levels(sections: List[Section]) -> Dict[str, int]:
    counts = {lvl: 0 for lvl in (HIGH, WARN, INFO, OK, ERROR)}
    for s in sections:
        for f in s.findings:
            counts[f.level] += 1
    return counts


def exit_code(sections: List[Section]) -> int:
    c = count_levels(sections)
    if c[ERROR]:
        return 3
    return 1 if c[HIGH] or c[WARN] else 0


def print_report(domain: str, sections: List[Section], resolver_label: str, verbose: bool) -> None:
    print(f"\n📧 {domain}   (DNS: {resolver_label})")
    for s in sections:
        print(f"\n[{s.name}]")
        for r in s.records:
            print(f"  记录: {r}")
        for f in s.findings:
            if f.level == OK and not verbose and s.name != "MX":
                continue
            print(f"  {LEVEL_ICON[f.level]} {f.message}")
        if verbose and s.extra.get("lookup_tree"):
            print("  SPF 查询树:")
            for line in s.extra["lookup_tree"]:
                print(f"    {line}")
        if not verbose and s.findings and all(f.level == OK for f in s.findings) and s.name != "MX":
            print(f"  ✅ 没发现问题")
    c = count_levels(sections)
    summary = " · ".join(f"{LEVEL_NAME[k]} {c[k]}" for k in (HIGH, WARN, INFO, ERROR) if c[k])
    print(f"\n总结: {summary or '没有发现问题 🎉'}")


def make_resolver(args):
    if args.doh:
        return DoHResolver(args.doh, timeout=args.timeout)
    return UDPResolver(args.dns or system_nameserver() or FALLBACK_DNS, timeout=args.timeout)


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0]
    if "@" in d:                      # 允许直接粘贴邮箱地址
        d = d.split("@")[-1]
    return d.rstrip(".")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="检查域名的 SPF / DKIM / DMARC / MX 配置，找出会被伪造或进垃圾箱的问题。")
    parser.add_argument("domains", nargs="+", help="要检查的域名（也可以直接写邮箱地址）")
    parser.add_argument("-s", "--selector", action="append", default=[],
                        help="DKIM 选择器（可多次指定或用逗号分隔）；不指定则猜常见选择器")
    parser.add_argument("--dns", help="DNS 服务器 IP（默认读 /etc/resolv.conf，读不到用 1.1.1.1）")
    parser.add_argument("--doh", nargs="?", const="https://cloudflare-dns.com/dns-query",
                        help="改用 DNS-over-HTTPS（JSON），可给 URL，默认 Cloudflare")
    parser.add_argument("--timeout", type=float, default=3.0, help="单次查询超时秒数（默认 3）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="也显示通过项和 SPF 查询树")
    args = parser.parse_args(argv)

    selectors = [s.strip() for item in args.selector for s in item.split(",") if s.strip()]
    resolver = make_resolver(args)
    worst, report = 0, {}
    for raw in args.domains:
        domain = normalize_domain(raw)
        try:
            encode_name(domain)
        except DNSError as e:
            print(e, file=sys.stderr)
            return 2
        sections = check_domain(domain, resolver, selectors or None)
        code = exit_code(sections)
        worst = max(worst, code)
        if args.json:
            report[domain] = {"sections": [asdict(s) for s in sections],
                              "summary": count_levels(sections), "exit_code": code}
        else:
            print_report(domain, sections, resolver.label, args.verbose)
    if args.json:
        print(json.dumps({"resolver": resolver.label, "domains": report},
                         ensure_ascii=False, indent=2))
    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
