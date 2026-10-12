//! One AdGuard-syntax line → one rule. No I/O.
use crate::pattern::Pat;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action { Allow, Block, Nx }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source { List(u64), User(usize) }

impl Source {
    pub fn tag(&self) -> String {
        match self { Source::List(id) => format!("L{id}"), Source::User(line) => format!("U{line}") }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Shape {
    /// `||d^`, `||d^|`: d and every subdomain.
    Suffix(String),
    /// `@@|d^|`: exactly d (allow only; Phase 2 table `allow_exact`).
    Exact(String),
    /// Everything else; None = can never match a hostname.
    Pattern(Option<Pat>),
    /// `/re/` body — RE2 syntax, case-insensitive, matched against the hostname.
    Regex(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub src: Source,
    pub action: Action,
    pub important: bool,
    pub badfilter: bool,
    pub shape: Shape,
    /// Pattern without modifiers, lowercased (regex keeps case): `$badfilter` identity.
    pub pattern: String,
    /// The trimmed line, for reports.
    pub text: String,
    /// `$client` IPs/CIDRs; None = no `$client` modifier.
    pub clients: Option<Clients>,
}

/// An address with a prefix length, masked (urlfilter clients.go add: `.Masked()`); a bare
/// address is /32 or /128. Ord = IPv4 before IPv6, then address, then prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpNet { pub addr: IpAddr, pub prefix: u8 }

impl IpNet {
    fn masked(addr: IpAddr, prefix: u8) -> IpNet {
        let addr = match addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) & (u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0))).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) & (u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0))).into()),
        };
        IpNet { addr, prefix }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}/{}", self.addr, self.prefix) }
}

/// Address or CIDR as golibs netutil IsValidIPString / IsValidIPPrefixString accept them
/// (v0.35.3 ip.go:168, prefix.go:51): dotted-decimal IPv4 without leading zeros, IPv6; prefix
/// bits decimal without sign or leading zeros, at most 32/128; no zone on a prefix. A zoned
/// address (`fe80::1%eth0`) is valid to golibs but not to std: it is refused as a name (safe).
impl std::str::FromStr for IpNet {
    type Err = ();
    fn from_str(s: &str) -> Result<IpNet, ()> {
        let (a, bits) = match s.rfind('/') { Some(i) => (&s[..i], Some(&s[i + 1..])), None => (s, None) };
        let addr: IpAddr = a.parse().map_err(|_| ())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match bits {
            None => max,
            Some(b) => {
                if b.is_empty() || !b.bytes().all(|c| c.is_ascii_digit()) || (b.len() > 1 && b.starts_with('0')) { return Err(()); }
                let n: u32 = b.parse().map_err(|_| ())?;
                if n > max as u32 { return Err(()); }
                n as u8
            }
        };
        Ok(IpNet::masked(addr, prefix))
    }
}

/// `$client` sets (urlfilter rules/clients.go): permitted and restricted (`~`) networks,
/// sorted and deduplicated so equality is set equality (negatesBadfilter compares them).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Clients { pub permit: Vec<IpNet>, pub deny: Vec<IpNet> }

/// Report class for an unknown modifier. The class is a status-file key and a refusal prefix, so
/// it must never carry an operator address: after a `$client`, an unknown piece is most likely
/// the rest of its value (`$client=A,B` typed for `A|B`, or a quoted value with a comma) → a
/// fixed class. Otherwise the name is echoed only if it has a modifier name's shape
/// (`[a-z][a-z0-9_-]*`), so no digit, dot, colon or quote can reach the class.
/// No class that can contain `client` has a `$` (fix round 4): report::redact_clients cuts at the
/// FIRST `$` of a refusal message, so the rule text's own `$` must come first for the class to
/// survive — hence `client modifier …` classes, and a name mentioning client is not echoed.
fn unknown_modifier(m: &str, after_client: bool) -> String {
    if after_client { return "client modifier with an invalid value".into(); }
    let name = m.split('=').next().unwrap_or(m);
    let shaped = name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && !name.contains("client");
    if shaped { format!("modifier ${name}") } else { "modifier with an invalid name".into() }
}

/// urlfilter rules/rules.go:71 splitWithEscapeCharacter: `\<sep>` is a literal sep, empty parts dropped.
fn split_escaped(s: &str, sep: char) -> Vec<String> {
    let (mut parts, mut cur, mut it) = (vec![], String::new(), s.chars().peekable());
    while let Some(c) = it.next() {
        if c == '\\' && it.peek() == Some(&sep) { cur.push(sep); it.next(); }
        else if c == sep { if !cur.is_empty() { parts.push(std::mem::take(&mut cur)); } }
        else { cur.push(c); }
    }
    if !cur.is_empty() { parts.push(cur); }
    parts
}

/// urlfilter rules/rule.go:259-330 parseClients / parseClient, IPs and CIDRs only.
fn parse_clients(value: &str) -> Result<Clients, String> {
    let empty = || "client modifier with an empty value".to_string();
    if value.is_empty() { return Err(empty()); }
    let mut c = Clients::default();
    for item in split_escaped(value, '|') {
        let (deny, mut v) = match item.strip_prefix('~') { Some(r) => (true, r.to_string()), None => (false, item.clone()) };
        let b = v.as_bytes();
        let quote = (b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[0] == b[b.len() - 1]).then(|| b[0] as char);
        if quote.is_some() { v = v[1..v.len() - 1].to_string(); }
        v = v.replace("\\,", ",");
        if let Some(q) = quote { v = v.replace(&format!("\\{q}"), &q.to_string()); }
        if v.is_empty() { return Err(empty()); }
        let net: IpNet = v.parse().map_err(|_| "client modifier with a client name".to_string())?;
        if deny { c.deny.push(net) } else { c.permit.push(net) }
    }
    for set in [&mut c.permit, &mut c.deny] { set.sort(); set.dedup(); }
    Ok(c)
}

impl Rule {
    /// Basic-rule level: 4 `@@$important`, 3 `$important`, 2 `@@`, 1 block.
    pub fn level(&self) -> u8 {
        match (self.action, self.important) {
            (Action::Allow, true) => 4,
            (Action::Block, true) => 3,
            (Action::Allow, false) => 2,
            (Action::Block, false) => 1,
            (Action::Nx, _) => 0,
        }
    }
    /// LMDB value: `L<id>` / `U<line>`, `!` appended for `$important`.
    pub fn value(&self) -> String {
        let mut v = self.src.tag();
        if self.important { v.push('!'); }
        v
    }
}

#[derive(Debug, PartialEq)]
pub enum Parsed { Skip, Rule(Rule), Unsupported(String) }

pub fn is_plain_name(d: &str) -> bool {
    !d.is_empty() && !d.starts_with('.') && !d.ends_with('.') && !d.contains("..")
        && d.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_')
}

/// DNS limits (RFC 1035 2.3.4): a label of at most 63 octets, a name of at most 255 in wire
/// format = 253 characters without the trailing dot. emit::wire drops longer names, so such a
/// rule is reported here instead of being dropped silently.
pub fn name_too_long(d: &str) -> bool { d.len() > 253 || d.split('.').any(|l| l.len() > 63) }

const COSMETIC: [&str; 5] = ["##", "#@#", "#$#", "#?#", "#%#"];

pub fn parse_line(raw: &str, src: Source) -> Parsed {
    let line = raw.trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('!') { return Parsed::Skip; }
    if line.starts_with('#') {
        // urlfilter rules/rule.go:49-72: `#` starts a comment unless it is a cosmetic marker.
        return if COSMETIC.iter().any(|m| line.starts_with(m)) {
            Parsed::Unsupported("cosmetic (ignored by AGH DNS)".into())
        } else { Parsed::Skip };
    }
    let (allow, body) = match line.strip_prefix("@@") { Some(b) => (true, b), None => (false, line) };
    let (pat, mods) = split_modifiers(body);
    let (mut important, mut badfilter, mut nx, mut clients) = (false, false, false, None);
    if let Some(m) = mods {
        for m in m.split(',').map(str::trim) {
            match m {
                "important" => important = true,
                // urlfilter network.go:960 setClientOptionHandler; a repeated $client replaces the earlier one.
                m if m == "client" || m.starts_with("client=") => match parse_clients(m["client".len()..].strip_prefix('=').unwrap_or("")) {
                    Ok(c) => clients = Some(c),
                    Err(class) => return Parsed::Unsupported(class),
                },
                "badfilter" => badfilter = true,
                "dnsrewrite=NXDOMAIN" | "dnsrewrite=NXDOMAIN;;" => nx = true,
                other => return Parsed::Unsupported(unknown_modifier(other, clients.is_some())),
            }
        }
    }
    if nx && allow { return Parsed::Unsupported("@@ with $dnsrewrite".into()); }
    let action = if nx { Action::Nx } else if allow { Action::Allow } else { Action::Block };
    let is_regex = pat.len() > 2 && pat.starts_with('/') && pat.ends_with('/');
    let pattern = if is_regex { pat.to_string() } else { pat.to_ascii_lowercase() };
    let suffix = pattern.strip_prefix("||")
        .and_then(|r| r.strip_suffix("^|").or_else(|| r.strip_suffix('^')))
        .filter(|d| is_plain_name(d));
    let exact = pattern.strip_prefix('|').and_then(|r| r.strip_suffix("^|")).filter(|d| allow && is_plain_name(d));
    let shape = if is_regex {
        Shape::Regex(pat[1..pat.len() - 1].to_string())
    } else if let Some(d) = suffix {
        Shape::Suffix(d.to_string())
    } else if let Some(d) = exact {
        Shape::Exact(d.to_string())
    } else {
        match Pat::parse(&pattern) { Ok(p) => Shape::Pattern(p), Err(class) => return Parsed::Unsupported(class) }
    };
    if let Shape::Suffix(d) | Shape::Exact(d) = &shape {
        if name_too_long(d) { return Parsed::Unsupported("name too long".into()); }
    }
    if nx && !matches!(shape, Shape::Suffix(_)) { return Parsed::Unsupported("$dnsrewrite on a non-plain pattern".into()); }
    if clients.is_some() {
        match &shape {
            // AGH checks answer addresses as hostnames with the client address; answers
            // are looked up in the global ip_block only, so such a rule cannot be scoped exactly.
            Shape::Suffix(d) if d.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
                return Parsed::Unsupported("client modifier on a rule that can match an answer address".into()),
            Shape::Suffix(_) => {}
            _ => return Parsed::Unsupported("client modifier on a non-plain rule".into()),
        }
    }
    Parsed::Rule(Rule { src, action, important, badfilter, shape, pattern, text: line.to_string(), clients })
}

/// `pattern$mods`; for `/re/$mods` only a `$` right after the closing `/` separates.
fn split_modifiers(body: &str) -> (&str, Option<&str>) {
    if body.starts_with('/') {
        if let Some(i) = body.rfind("/$") { if i > 0 { return (&body[..=i], Some(&body[i + 2..])); } }
        return (body, None);
    }
    match body.rfind('$') { Some(i) => (&body[..i], Some(&body[i + 1..])), None => (body, None) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(s: &str) -> Parsed { parse_line(s, Source::List(1)) }
    fn rule(s: &str) -> Rule { match p(s) { Parsed::Rule(r) => r, other => panic!("{s}: {other:?}") } }

    #[test] fn skips() { for s in ["", "   ", "! comment", "# comment", "#"] { assert_eq!(p(s), Parsed::Skip, "{s:?}"); } }
    #[test] fn cosmetic_reported() { assert!(matches!(p("##||supercell.com^$important"), Parsed::Unsupported(c) if c.starts_with("cosmetic"))); }
    #[test] fn plain_suffix() {
        for s in ["||Ads.Example.com^", "||ads.example.com^|"] {
            let r = rule(s); assert_eq!(r.shape, Shape::Suffix("ads.example.com".into())); assert_eq!(r.level(), 1); assert_eq!(r.value(), "L1");
        }
    }
    #[test] fn levels_and_values() {
        assert_eq!(rule("@@||a.com^$important").level(), 4);
        assert_eq!(rule("||a.com^$important").level(), 3);
        assert_eq!(rule("@@||a.com^").level(), 2);
        assert_eq!(rule("||a.com^$important").value(), "L1!");
        assert_eq!(parse_line_user("@@||a.com^$important", 7).value(), "U7!");
    }
    fn parse_line_user(s: &str, n: usize) -> Rule { match parse_line(s, Source::User(n)) { Parsed::Rule(r) => r, o => panic!("{o:?}") } }
    #[test] fn exact_allow_only() {
        assert_eq!(rule("@@|a.com^|").shape, Shape::Exact("a.com".into()));
        assert!(matches!(rule("|a.com^|").shape, Shape::Pattern(Some(_))));
    }
    #[test] fn nx() {
        for s in ["||v.com^$dnsrewrite=NXDOMAIN;;", "||v.com^$dnsrewrite=NXDOMAIN,important"] {
            let r = rule(s); assert_eq!(r.action, Action::Nx); assert_eq!(r.shape, Shape::Suffix("v.com".into()));
        }
        assert!(matches!(p("||a*.com^$dnsrewrite=NXDOMAIN"), Parsed::Unsupported(_)));
        assert!(matches!(p("@@||a.com^$dnsrewrite=NXDOMAIN"), Parsed::Unsupported(_)));
    }
    #[test] fn unsupported_modifiers() {
        for s in ["||^$dnstype=ANY,dnsrewrite=REFUSED,important", "@@||go.zen.com^$client='MyNetwork'", "||a.com^$denyallow=b.com"] {
            assert!(matches!(p(s), Parsed::Unsupported(c) if c.contains("modifier")), "{s}");
        }
    }
    #[test] fn badfilter() { let r = rule("||pl.ua^$badfilter"); assert!(r.badfilter); assert_eq!(r.pattern, "||pl.ua^"); }
    #[test] fn regex_keeps_case_and_modifiers() {
        let r = rule(r"/^88\.208\.22\.[1234]$/"); assert_eq!(r.shape, Shape::Regex(r"^88\.208\.22\.[1234]$".into()));
        let r = rule(r"/^A\d$/$important"); assert!(r.important); assert_eq!(r.shape, Shape::Regex(r"^A\d$".into()));
    }
    #[test] fn name_too_long_is_unsupported() {
        let (l63, l64) = ("a".repeat(63), "a".repeat(64));
        assert_eq!(rule(&format!("||{l63}.example^")).shape, Shape::Suffix(format!("{l63}.example")));
        let n253 = format!("{}abcdefghi.com", "abcdefghi.".repeat(24)); assert_eq!(n253.len(), 253);
        assert!(matches!(rule(&format!("||{n253}^")).shape, Shape::Suffix(_)));
        for s in [format!("||{l64}.example^"), format!("@@|{l64}.example^|"), format!("||x{n253}^"), format!("||{l64}^$dnsrewrite=NXDOMAIN")] {
            assert_eq!(unsup(&s), "name too long", "{s}");
        }
        assert_eq!(parse_line(&format!("||{l64}.example^"), Source::User(4)), Parsed::Unsupported("name too long".into()));
    }
    #[test] fn crlf_bom_trailing() { assert_eq!(rule("\u{feff}||a.com^  \r").shape, Shape::Suffix("a.com".into())); }

    // $client (urlfilter rules/rule.go:259-330 parseClients/parseClient, clients.go add).
    fn nets(v: &[IpNet]) -> Vec<String> { v.iter().map(|n| n.to_string()).collect() }
    fn cl(s: &str) -> Clients { rule(s).clients.unwrap_or_else(|| panic!("{s}: no clients")) }
    fn unsup(s: &str) -> String { match p(s) { Parsed::Unsupported(c) => c, o => panic!("{s}: {o:?}") } }
    #[test] fn client_ip() {
        let r = rule("||TV.example^$client=127.0.0.1,important");
        assert_eq!(r.shape, Shape::Suffix("tv.example".into())); assert_eq!(r.level(), 3); assert_eq!(r.value(), "L1!");
        let c = r.clients.unwrap(); assert_eq!(nets(&c.permit), ["127.0.0.1/32"]); assert!(c.deny.is_empty());
        assert_eq!(rule("||a.com^").clients, None);
    }
    #[test] fn client_cidr_is_masked() { assert_eq!(nets(&cl("||a.com^$client=10.1.2.3/8").permit), ["10.0.0.0/8"]); }
    #[test] fn client_ipv6() {
        assert_eq!(nets(&cl("||a.com^$client=2001:DB8::1").permit), ["2001:db8::1/128"]);
        assert_eq!(nets(&cl("||a.com^$client=2001:db8:ff::/32").permit), ["2001:db8::/32"]);
    }
    #[test] fn client_negation_and_quotes() {
        let c = cl(r#"@@||a.com^$client=~'192.0.2.1'|"198.51.100.7/24",important"#);
        assert_eq!(nets(&c.deny), ["192.0.2.1/32"]); assert_eq!(nets(&c.permit), ["198.51.100.0/24"]);
        assert_eq!(nets(&cl("||a.com^$client=~2001:db8::/32").deny), ["2001:db8::/32"]);
    }
    #[test] fn client_list_split_dedup_sorted() {
        // Empty parts are skipped (rules.go splitWithEscapeCharacter); a set: sorted, no duplicates.
        let c = cl("||a.com^$client=192.0.2.9||10.0.0.1|192.0.2.9/32");
        assert_eq!(nets(&c.permit), ["10.0.0.1/32", "192.0.2.9/32"]);
    }
    #[test] fn client_escaped_pipe_is_one_value() {
        // `\|` is not a separator: "10.0.0.1|10.0.0.2" is one value, not an address → a name.
        assert_eq!(unsup(r"||a.com^$client=10.0.0.1\|10.0.0.2"), "client modifier with a client name");
    }
    #[test] fn client_name_or_tag_unsupported() {
        for s in ["@@||go.zen.com^$client='MyNetwork'", "||a.com^$client=Frank", "||a.com^$client=~Mom|10.0.0.1",
                  "||a.com^$client=01.2.3.4", "||a.com^$client=1.2.3.0/08", "||a.com^$client=1.2.3.0/+8",
                  "||a.com^$client=1.2.3.0/33", "||a.com^$client=fe80::1%eth0", "||a.com^$client='~1.2.3.4'"] {
            assert_eq!(unsup(s), "client modifier with a client name", "{s}");
        }
        for s in ["||a.com^$client=", "||a.com^$client=~", "||a.com^$client"] {
            assert_eq!(unsup(s), "client modifier with an empty value", "{s}");
        }
    }
    #[test] fn client_on_non_plain_unsupported() {
        for s in ["||a*.com^$client=1.2.3.4", "@@|a.com^|$client=1.2.3.4", r"/^ads\./$client=1.2.3.4", "-ads1.$client=1.2.3.4"] {
            assert_eq!(unsup(s), "client modifier on a non-plain rule", "{s}");
        }
        // Answer addresses are checked as hostnames; ip_block is global → cannot scope it.
        for s in ["||212.117.190.201^$client=1.2.3.4", "||3.4^$client=1.2.3.4"] {
            assert_eq!(unsup(s), "client modifier on a rule that can match an answer address", "{s}");
        }
    }
    #[test] fn client_comma_typo_class_has_no_address() {
        // Fix round 2: the piece after an unescaped comma must not become the class name.
        for s in ["||x.example^$client=10.20.30.43,10.20.30.44", "||y.example^$client=10.20.30.45, 10.20.30.46",
                  "||w.example^$important,client=10.0.0.1,fd00::9"] {
            assert_eq!(unsup(s), "client modifier with an invalid value", "{s}");
        }
        // A quoted value split by the comma: its first half (`'a`) is already a client name.
        assert_eq!(unsup("||z.example^$client='a,10.20.30.47'"), "client modifier with a client name");
        // Without $client: real modifier names are still named, anything else is not echoed.
        assert_eq!(unsup("||a.com^$denyallow=b.com"), "modifier $denyallow");
        assert_eq!(unsup("||a.com^$clientx=10.20.30.65"), "modifier with an invalid name");
        for s in ["||a.com^$10.20.30.48", "||a.com^$important,fd00::1", "||a.com^$'x'"] {
            assert_eq!(unsup(s), "modifier with an invalid name", "{s}");
        }
    }
    #[test] fn client_with_dnsrewrite() {
        let r = rule("||cnx.example^$client=127.0.0.0/8,dnsrewrite=NXDOMAIN");
        assert_eq!(r.action, Action::Nx); assert_eq!(nets(&r.clients.unwrap().permit), ["127.0.0.0/8"]);
    }
}
