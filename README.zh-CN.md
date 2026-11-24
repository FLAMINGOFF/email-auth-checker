# 邮件域名配置检查器（Email Auth Checker）

[English](README.md) | **简体中文**

一个很小的 Python 命令行工具：检查域名的 **SPF、DKIM、DMARC**（以及 MX）DNS 记录，
找出会让别人**轻松冒充你的域名发信**、或者让你的正常邮件进垃圾箱的配置错误。

它自带一个用 `socket` 写的**迷你 DNS 客户端**（走 UDP，响应被截断时自动改 TCP），
所以不需要 `dnspython`。也可以用 `--doh` 改走 **DNS-over-HTTPS**。

只用 Python 标准库，不需要 `pip install`，也不需要 API Key。Python 3.8+。

## 怎么用

```bash
python3 email_auth_check.py example.com                # 检查一个域名
python3 email_auth_check.py you@example.com            # 直接粘贴邮箱地址也行
python3 email_auth_check.py example.com -s google      # 指定 DKIM 选择器（可重复或逗号分隔）
python3 email_auth_check.py example.com -v             # 也显示通过项和 SPF 查询树
python3 email_auth_check.py example.com --json         # JSON 输出
python3 email_auth_check.py example.com --dns 223.5.5.5  # 指定 DNS 服务器（默认读 /etc/resolv.conf）
python3 email_auth_check.py example.com --doh          # DNS-over-HTTPS（默认 Cloudflare）
python3 email_auth_check.py example.com --doh https://dns.alidns.com/resolve  # 国内可用的 DoH
python3 email_auth_check.py a.com b.com c.com          # 一次查多个域名

python3 -m unittest -v                                 # 离线测试（假 DNS 数据，不联网）
```

示例输出：

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

| 退出码 | 含义 |
|---|---|
| `0` | 没有高危和警告 |
| `1` | 发现问题 |
| `2` | 域名不合法 |
| `3` | DNS 查询失败（超时、SERVFAIL 等） |

## 一分钟看懂这三条记录

```
            "From: boss@example.com"
                     │
     ┌───────────────┼──────────────────┐
     ▼               ▼                  ▼
   SPF             DKIM               DMARC
 “哪些服务器       “这封邮件有没有     “SPF/DKIM 失败（或和 From 域名
  可以代表          用 DNS 里公布的     对不上）时，接收方该怎么办？
  example.com      密钥签名？”         报告发到哪？”
  发信？”
 TXT @ example.com TXT @ <选择器>.     TXT @ _dmarc.example.com
                   _domainkey.example.com
```

单靠 SPF 和 DKIM **保护不了收件人看到的 `From:` 地址**：SPF 检查的是隐藏的信封发件人，
DKIM 只证明“某个域名”签了名。DMARC 把它们和 `From:` 域名绑定（对齐），并告诉接收方
失败了就拒收。所以只有 SPF + DKIM、没有 DMARC（或 `p=none`）的域名照样能被伪造。

## 检查了什么

**MX**
- 没有 MX / Null MX（`0 .`）：域名不收邮件。停放的域名也要配 `v=spf1 -all` + `p=reject`，
  攻击者恰恰喜欢冒充这种没人管的域名。

**SPF**（RFC 7208）
- 没有记录，或有多条 `v=spf1`（多条 = `permerror`，SPF 直接失效）
- `+all`（谁都能发）、`?all`（中立）、缺少 `all`、`all` 不在最后；`~all` 给出提示
- 无法识别的机制（比如拼错成 `inclde:`）、非法的 `ip4:`/`ip6:`、超大网段（`ip4:0.0.0.0/0`）
- 已弃用的 `ptr`
- **10 次 DNS 查询上限**：递归展开整棵 `include:` / `redirect=` 树，统计 `include`、`a`、
  `mx`、`ptr`、`exists`、`redirect`。超过 10 次，**每一封**邮件的 SPF 都是 `permerror`。
  这是现实中最常见的 SPF 故障（各种 SaaS 的 include 越叠越多）。`-v` 会打印查询树。
- include 指向没有 SPF 的域名、include 循环、超过 2 次空查询

**DMARC**（RFC 7489）
- 没有记录（子域名会回退到组织域，再看 `sp=`）
- 多条记录、`v=DMARC1` 不是第一个标签、`p=` 缺失或无效
- `p=none`（只监控）、`sp=` / `np=` 比 `p=` 弱、`pct` < 100
- 没有 `rua`（收不到报告）、不是 `mailto:` 的地址
- **外部报告授权**：如果 `rua` 把报告发到别的域名，那个域名必须发布
  `example.com._report._dmarc.<对方域名>`，否则报告会被悄悄丢掉。工具会去查这条记录。
- 无效的 `adkim`/`aspf`、未知标签、`ruf` 的提示

**DKIM**（RFC 6376、RFC 8301、RFC 8463）
- 选择器无法通过 DNS 列出来，所以不加 `-s` 时会猜约 35 个常见的（`google`、`selector1`、
  `k1`、`default` 等）。真正的选择器在你发出的邮件头 `DKIM-Signature:` 的 `s=` 里。
- **RSA 密钥长度**：把 `p=` 做 Base64 解码，用一个很小的 ASN.1 解析器读 DER 格式的
  `SubjectPublicKeyInfo`，取出模数位数。< 1024 位 = 高危（RFC 8301 要求接收方拒绝，
  512 位密钥已经被实际分解用来伪造），1024 = 警告，≥ 2048 = 通过。也能识别 Ed25519。
- `p=` 为空（密钥已吊销）、Base64 损坏、`t=y`（测试模式）、只允许 `h=sha1`

## DNS 客户端是怎么工作的

```
build_query()   头部（ID、RD 递归标志）+ 域名标签 + 查询类型 + EDNS0 OPT（声明能收 4096 字节 UDP）
      │  UDP :53
      ▼
parse_response() 校验 ID → 头部标志 → 跳过问题区 → 读应答区
                 （处理域名压缩指针，带防成环保护）
      │  TC=1（被截断）？ → 改用 TCP 重发（前面加 2 字节长度）
      ▼
TXT 数据 = <长度><内容><长度><内容>… → 拼接起来（长 DKIM 公钥会拆成好几段 255 字节）
NXDOMAIN → “没有记录”；  SERVFAIL / REFUSED / 超时 → DNSError（退出码 3）
```

CNAME（邮件服务商托管 DKIM 密钥时很常见）由递归 DNS 服务器跟随；客户端只保留和查询类型一致的应答。

## 局限

- **DKIM 无法证明“不存在”。**“没找到 DKIM”只代表猜的那些选择器都不存在，请用 `-s` 指定。
- **这只检查 DNS，不检查实际邮件流。** 你的服务器到底有没有签名、SPF 有没有漏掉某个发信源，
  只有 DMARC 聚合报告能告诉你（这正是 `rua` 的用处）。
- 组织域是近似算出来的（取最后两段，外加 `com.cn`、`co.uk` 等一小份列表），没有用完整的 Public Suffix List。
- 不展开 SPF 宏（`%{d}`），也不统计每个 `mx` 最多 10 个地址的子上限。
- 普通 UDP DNS 没有认证（不做 DNSSEC 验证）。在不信任的网络上请用 `--doh`。
- 没有覆盖：MTA-STS、TLS-RPT、BIMI、DNSSEC。

## 现实中的同类工具

[MXToolbox](https://mxtoolbox.com/)、[dmarcian](https://dmarcian.com/domain-checker/)、
[Google Admin Toolbox CheckMX](https://toolbox.googleapps.com/apps/checkmx/)、
[learndmarc.com](https://www.learndmarc.com/)（可视化演示，很适合入门）；
报告分析类：Postmark DMARC、Valimail、EasyDMARC。
