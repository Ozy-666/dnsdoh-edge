//! Rules → tables. No I/O.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::pattern::Key;
use crate::rule::{Action, Clients, IpNet, Rule, Shape};

#[derive(Clone, Debug, PartialEq)]
pub struct Entry { pub level: u8, pub value: String, pub lua: Vec<String> }
impl Entry { pub fn line(&self) -> String { format!("{}\t{}\t{}", self.level, self.value, self.lua.join("\x1f")) } }

type Plain = BTreeMap<String, (u8, String)>;

/// One `$client` rule: level 0 = `$dnsrewrite=NXDOMAIN`, else the basic level.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientEntry { pub level: u8, pub value: String, pub permit: Vec<IpNet>, pub deny: Vec<IpNet> }
impl ClientEntry {
    /// `<level|nx>\t<value>\t<permit csv>\t<deny csv>`.
    pub fn line(&self) -> String {
        let csv = |v: &[IpNet]| v.iter().map(IpNet::to_string).collect::<Vec<_>>().join(",");
        let lvl = if self.level == 0 { "nx".to_string() } else { self.level.to_string() };
        format!("{lvl}\t{}\t{}\t{}", self.value, csv(&self.permit), csv(&self.deny))
    }
}

#[derive(Default, Debug)]
pub struct Tables {
    pub allow_exact: Plain,
    pub allow: Plain,
    pub block: Plain,
    pub block_nx: BTreeMap<String, String>,
    pub pattern: BTreeMap<String, Vec<Entry>>,
    pub pattern_open: BTreeMap<String, Vec<Entry>>,
    pub scan: Vec<Entry>,
    pub all_patterns: Vec<Entry>,
    pub max_run: usize,
    pub ip_block: BTreeMap<[u8; 4], String>,
    pub rewrite: BTreeMap<String, String>,
    /// `$client` rules by domain; each key also carries its ancestors' entries.
    pub client: BTreeMap<String, Vec<ClientEntry>>,
}

#[derive(Default, Debug)]
pub struct Notes { pub client_rules: usize, pub badfiltered: usize, pub pruned_allows: usize, pub unsupported: Vec<(String, String)>, pub conflicts: Vec<String> }

pub fn ancestors_or_self(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.find('.').map(|i| &n[i + 1..]))
}

fn keep_max(map: &mut Plain, k: &str, lvl: u8, v: String) {
    if map.get(k).map_or(true, |(l, _)| *l < lvl) { map.insert(k.to_string(), (lvl, v)); }
}

/// lookupSuffix returns only the longest stored suffix, so each entry carries the
/// highest level (and its value) found on itself or any ancestor in the same table.
fn propagate(map: &mut Plain) {
    let snap = map.clone();
    for (name, v) in map.iter_mut() {
        for a in ancestors_or_self(name).skip(1) {
            if let Some(x) = snap.get(a) { if x.0 > v.0 { *v = x.clone(); } }
        }
    }
}

fn parse_ipv4(d: &str) -> Option<[u8; 4]> { d.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets()) }

/// `/^a\.b\.c\.…/` pins a /24 → test all 256 addresses as hostname strings;
/// `/^a\.b\.…/` (first two octets literal) pins a /16 → all 65 536 (e.g. `/^139\.45\.19[5-7]\.\d{1,3}/`).
/// Anything else (unanchored, unescaped dots) is reported, never approximated.
fn expand_ip_regex(re: &str) -> Result<Vec<[u8; 4]>, String> {
    let pin24 = regex::Regex::new(r"^\^(\d{1,3})\\\.(\d{1,3})\\\.(\d{1,3})\\\.").unwrap();
    let pin16 = regex::Regex::new(r"^\^(\d{1,3})\\\.(\d{1,3})\\\.").unwrap();
    let caps = pin24.captures(re).or_else(|| pin16.captures(re)).ok_or("regex (not a pinned IPv4 /24 or /16)".to_string())?;
    let oct = |i: usize| caps[i].parse::<u8>().map_err(|_| "IP regex with an invalid octet".to_string());
    let (a, b) = (oct(1)?, oct(2)?);
    let thirds: Vec<u8> = if caps.get(3).is_some() { vec![oct(3)?] } else { (0..=255u8).collect() };
    let full = regex::Regex::new(&format!("(?i){re}")).map_err(|e| format!("regex does not compile: {e}"))?;
    Ok(thirds.into_iter().flat_map(|c| (0..=255u8).map(move |d| [a, b, c, d]))
        .filter(|ip| full.is_match(&format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))).collect())
}

pub fn resolve(rules: Vec<Rule>, rewrites: &[(String, String)]) -> (Tables, Notes) {
    let mut n = Notes::default();
    // $badfilter (urlfilter rules/network.go negatesBadfilter): same action, pattern, other modifiers.
    // Excludes Action::Nx (dnsrewrite=NXDOMAIN): removeBadfilterRules only runs in the network-rule
    // matching path (rules/match.go GetDNSBasicRule / NewMatchingResult, match.go:97,:174). The
    // dnsrewrite path reads raw NetworkRules with no badfilter step (dnsresult.go:64-85
    // DNSRewrites(), used by AGH filtering/dnsrewrite.go:79) and DNSRewritesAll keeps any rule with
    // DNSRewrite != nil — including one that itself carries $badfilter. So an Nx rule never negates
    // another Nx rule, and an Nx rule marked $badfilter stays live rather than being dropped.
    // The identity includes the $client sets (negatesBadfilter compares permitted/restricted clients).
    let bad: BTreeSet<(Action, String, bool, Option<Clients>)> = rules.iter()
        .filter(|r| r.badfilter && r.action != Action::Nx)
        .map(|r| (r.action, r.pattern.clone(), r.important, r.clients.clone())).collect();
    let rules: Vec<Rule> = rules.into_iter().filter(|r| {
        if r.action == Action::Nx { return true; }
        if r.badfilter { return false; }
        let hit = bad.contains(&(r.action, r.pattern.clone(), r.important, r.clients.clone()));
        n.badfiltered += hit as usize;
        !hit
    }).collect();

    let mut t = Tables::default();
    let mut ip_allow: HashMap<[u8; 4], u8> = HashMap::new();
    let mut ip_blk: HashMap<[u8; 4], (u8, String)> = HashMap::new();
    let mut pats: Vec<(Key, Entry)> = vec![];
    let mut add_ip = |ip: [u8; 4], a: Action, lvl: u8, v: String| {
        if a == Action::Allow { let e = ip_allow.entry(ip).or_insert(0); *e = (*e).max(lvl); }
        else if ip_blk.get(&ip).map_or(true, |x| x.0 < lvl) { ip_blk.insert(ip, (lvl, v)); }
    };
    for r in &rules {
        let lvl = r.level();
        // Client rules only ever go to table `client`: never global, pruning or conflicts.
        if let (Some(c), Shape::Suffix(d)) = (&r.clients, &r.shape) {
            n.client_rules += 1;
            t.client.entry(d.clone()).or_default().push(ClientEntry { level: lvl, value: r.value(), permit: c.permit.clone(), deny: c.deny.clone() });
            continue;
        }
        match (&r.shape, r.action) {
            (Shape::Suffix(d), Action::Nx) => { t.block_nx.entry(d.clone()).or_insert_with(|| r.value()); }
            (Shape::Suffix(d), a) => {
                keep_max(if a == Action::Allow { &mut t.allow } else { &mut t.block }, d, lvl, r.value());
                if let Some(ip) = parse_ipv4(d) { add_ip(ip, a, lvl, r.value()); }
                else if a == Action::Block && d.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                    n.unsupported.push(("response side: plain rule can match part of an IP".into(), r.text.clone()));
                }
            }
            (Shape::Exact(d), _) => {
                keep_max(&mut t.allow_exact, d, lvl, r.value());
                // Shape::Exact is allow-only (rule.rs is_plain_name/exact gating), but the answer
                // address still needs to reach the IP-precedence table, same as a Suffix allow.
                if let Some(ip) = parse_ipv4(d) { add_ip(ip, Action::Allow, lvl, r.value()); }
            }
            (Shape::Pattern(None), _) => n.unsupported.push(("never matches a [a-z0-9._-] hostname".into(), r.text.clone())),
            (Shape::Pattern(Some(p)), _) => {
                if p.may_match_ip() { n.unsupported.push(("response side: pattern can match an IP".into(), r.text.clone())); }
                pats.push((p.key(), Entry { level: lvl, value: r.value(), lua: p.lua_patterns() }));
            }
            (Shape::Regex(re), a) => match expand_ip_regex(re) {
                Ok(ips) => {
                    n.unsupported.push(("IP regex: applied to answers only, not to IP-literal question names".into(), r.text.clone()));
                    for ip in ips { add_ip(ip, a, lvl, r.value()); }
                }
                Err(class) => n.unsupported.push((class, r.text.clone())),
            },
        }
    }

    propagate(&mut t.block);
    propagate(&mut t.allow);
    for (name, v) in t.allow_exact.iter_mut() {
        for a in ancestors_or_self(name) { if let Some(x) = t.allow.get(a) { if x.0 > v.0 { *v = x.clone(); } } }
    }
    // C++ checks allows before blocks → drop an allow that a
    // higher-level block covers entirely; a higher-level block strictly below an allow is a conflict.
    let block = &t.block;
    let above = |name: &str| ancestors_or_self(name).filter_map(|a| block.get(a).map(|x| x.0)).max().unwrap_or(0);
    let before = t.allow.len() + t.allow_exact.len();
    let allow: Plain = t.allow.iter().filter(|(k, v)| above(k) < v.0).map(|(k, v)| (k.clone(), v.clone())).collect();
    let exact: Plain = t.allow_exact.iter().filter(|(k, v)| above(k) < v.0).map(|(k, v)| (k.clone(), v.clone())).collect();
    t.allow = allow;
    t.allow_exact = exact;
    n.pruned_allows = before - t.allow.len() - t.allow_exact.len();
    for (b, (lb, _)) in &t.block {
        for a in ancestors_or_self(b).skip(1) {
            if let Some((la, _)) = t.allow.get(a) {
                if la < lb { n.conflicts.push(format!("block {b} (level {lb}) below allow {a} (level {la})")); }
            }
        }
    }

    for (k, e) in pats {
        t.all_patterns.push(e.clone());
        match k {
            Key::Tail(k) => t.pattern.entry(k).or_default().push(e),
            Key::Open(k) => { t.max_run = t.max_run.max(k.split('.').count()); t.pattern_open.entry(k).or_default().push(e) }
            Key::Scan => t.scan.push(e),
        }
    }
    let snap = t.pattern.clone();
    for (k, v) in t.pattern.iter_mut() {
        for a in ancestors_or_self(k).skip(1) { if let Some(x) = snap.get(a) { v.extend(x.iter().cloned()); } }
    }

    // lookupSuffix returns only the longest stored key: carry the ancestors' client entries too.
    let snap = t.client.clone();
    for (k, v) in t.client.iter_mut() {
        for a in ancestors_or_self(k).skip(1) { if let Some(x) = snap.get(a) { v.extend(x.iter().cloned()); } }
    }

    for (ip, (lb, v)) in ip_blk { if ip_allow.get(&ip).copied().unwrap_or(0) < lb { t.ip_block.insert(ip, v); } }
    for (name, ip) in rewrites { t.rewrite.insert(name.clone(), format!("A {ip}")); }
    (t, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{parse_line, Parsed, Source};
    fn rules(lines: &[&str]) -> Vec<Rule> {
        lines.iter().enumerate().filter_map(|(i, l)| match parse_line(l, Source::User(i + 1)) { Parsed::Rule(r) => Some(r), _ => None }).collect()
    }
    #[test] fn badfilter_removes_exact_twin_only() {
        let (t, n) = resolve(rules(&["||pl.ua^", "||pl.ua^$badfilter", "||pl.ua^$dnsrewrite=NXDOMAIN"]), &[]);
        assert!(t.block.is_empty()); assert_eq!(n.badfiltered, 1); assert!(t.block_nx.contains_key("pl.ua"));
    }
    #[test] fn badfilter_does_not_negate_dnsrewrite() {
        // Counterexample from review: a $dnsrewrite rule is never negated by a $badfilter twin
        // (dnsresult.go DNSRewritesAll keeps any rule with DNSRewrite != nil, badfilter or not).
        let (t, n) = resolve(rules(&["||pl.ua^$dnsrewrite=NXDOMAIN", "||pl.ua^$dnsrewrite=NXDOMAIN,badfilter"]), &[]);
        assert!(t.block_nx.contains_key("pl.ua"));
        assert_eq!(n.badfiltered, 0);
    }
    #[test] fn important_block_prunes_covered_allow() {
        let (t, n) = resolve(rules(&["||ads.com^$important", "@@||x.ads.com^", "@@||y.ads.com^$important"]), &[]);
        assert!(!t.allow.contains_key("x.ads.com")); assert!(t.allow.contains_key("y.ads.com")); assert_eq!(n.pruned_allows, 1);
        assert!(n.conflicts.is_empty());
    }
    #[test] fn important_block_below_allow_is_a_conflict() {
        let (_, n) = resolve(rules(&["@@||ads.com^", "||x.ads.com^$important"]), &[]);
        assert_eq!(n.conflicts.len(), 1);
    }
    #[test] fn level_propagates_to_children() {
        let (t, _) = resolve(rules(&["||ads.com^$important", "||x.ads.com^"]), &[]);
        assert_eq!(t.block["x.ads.com"], (3, "U1!".to_string()));
    }
    #[test] fn tail_keys_inherit_ancestor_entries() {
        let (t, _) = resolve(rules(&["||a*.b.com^", "||c*.x.b.com^"]), &[]);
        assert_eq!(t.pattern["x.b.com"].len(), 2); assert_eq!(t.pattern["b.com"].len(), 1);
    }
    #[test] fn ips_and_regex_expansion() {
        let (t, n) = resolve(rules(&["||212.117.190.201^", r"/^139\.45\.197\.2(4[0-9]|5[0-4])/", "@@||139.45.197.245^$important", "/62.76.25.2(7|8)/"]), &[]);
        assert!(t.ip_block.contains_key(&[212, 117, 190, 201]));
        assert!(t.ip_block.contains_key(&[139, 45, 197, 240]) && t.ip_block.contains_key(&[139, 45, 197, 254]));
        assert!(!t.ip_block.contains_key(&[139, 45, 197, 245]) && !t.ip_block.contains_key(&[139, 45, 197, 239]));
        assert!(n.unsupported.iter().any(|(c, r)| c.contains("pinned") && r.contains("62.76")));
    }
    #[test] fn regex_pinned_to_a_16_expands_exactly() {
        let (t, n) = resolve(rules(&[r"/^139\.45\.19[5-7]\.\d{1,3}/"]), &[]);
        for c in 195..=197u8 { for d in 0..=255u8 { assert!(t.ip_block.contains_key(&[139, 45, c, d]), "139.45.{c}.{d}"); } }
        for d in 0..=255u8 { assert!(!t.ip_block.contains_key(&[139, 45, 194, d]) && !t.ip_block.contains_key(&[139, 45, 198, d])); }
        assert_eq!(t.ip_block.len(), 3 * 256);
        assert!(n.unsupported.iter().all(|(c, _)| !c.contains("pinned")));
        // not literal octets (`.` unescaped, unanchored): still reported, never approximated
        let (t, n) = resolve(rules(&["/^2.59.219.121/", "/62.76.25.2(7|8)/"]), &[]);
        assert!(t.ip_block.is_empty());
        assert_eq!(n.unsupported.iter().filter(|(c, _)| c.contains("pinned")).count(), 2);
    }
    #[test] fn exact_ip_allow_reaches_ip_table() {
        // Counterexample from review: an exact-IP allow must reach ip_allow so it can outrank a
        // lower-level suffix IP block (max(2,1) allows), not silently leave the block in ip_block.
        let (t, _) = resolve(rules(&["||1.2.3.4^", "@@|1.2.3.4^|"]), &[]);
        assert!(!t.ip_block.contains_key(&[1, 2, 3, 4]));
    }
    #[test] fn rewrites_table() {
        let (t, _) = resolve(vec![], &[("a.example.net".into(), "192.0.2.10".into())]);
        assert_eq!(t.rewrite["a.example.net"], "A 192.0.2.10");
    }
    #[test] fn open_and_scan() {
        let (t, _) = resolve(rules(&["||an.yandex.", "-ads1."]), &[]);
        assert!(t.pattern_open.contains_key("an.yandex")); assert_eq!(t.scan.len(), 1); assert_eq!(t.max_run, 2); assert_eq!(t.all_patterns.len(), 2);
    }

    // $client: own table, ancestor inheritance, never global, badfilter identity.
    fn ce(level: u8, value: &str, permit: &[&str], deny: &[&str]) -> ClientEntry {
        let n = |v: &[&str]| v.iter().map(|s| s.parse::<crate::rule::IpNet>().unwrap()).collect();
        ClientEntry { level, value: value.into(), permit: n(permit), deny: n(deny) }
    }
    #[test] fn client_rules_stay_out_of_global_tables() {
        let (t, n) = resolve(rules(&["||tv.example^$client=127.0.0.1,important", "||cnx.example^$client=127.0.0.0/8,dnsrewrite=NXDOMAIN",
                                     "@@||ok.example^$client=~192.0.2.1"]), &[]);
        assert!(t.block.is_empty() && t.allow.is_empty() && t.allow_exact.is_empty() && t.block_nx.is_empty());
        assert_eq!(t.client["tv.example"], vec![ce(3, "U1!", &["127.0.0.1/32"], &[])]);
        assert_eq!(t.client["cnx.example"], vec![ce(0, "U2", &["127.0.0.0/8"], &[])]);
        assert_eq!(t.client["ok.example"], vec![ce(2, "U3", &[], &["192.0.2.1/32"])]);
        assert_eq!(n.client_rules, 3);
    }
    #[test] fn client_keys_inherit_ancestor_entries() {
        let (t, _) = resolve(rules(&["||tv.example^$client=127.0.0.1", "@@||ok.tv.example^$client=127.0.0.1,important"]), &[]);
        assert_eq!(t.client["tv.example"], vec![ce(1, "U1", &["127.0.0.1/32"], &[])]);
        assert_eq!(t.client["ok.tv.example"], vec![ce(4, "U2!", &["127.0.0.1/32"], &[]), ce(1, "U1", &["127.0.0.1/32"], &[])]);
    }
    #[test] fn client_rules_take_no_part_in_pruning_or_conflicts() {
        let (t, n) = resolve(rules(&["@@||conf.example^", "||x.conf.example^$client=1.2.3.4,important",
                                     "||ads.com^$client=1.2.3.4,important", "@@||x.ads.com^"]), &[]);
        assert!(n.conflicts.is_empty()); assert_eq!(n.pruned_allows, 0); assert!(t.allow.contains_key("x.ads.com"));
    }
    #[test] fn client_badfilter_identity_includes_clients() {
        // urlfilter negatesBadfilter (network.go:496): permitted/restricted client sets must be equal.
        let (t, n) = resolve(rules(&["||a.com^$client=1.2.3.4", "||a.com^$client=1.2.3.4,badfilter",
                                     "||b.com^$client=1.2.3.4", "||b.com^$badfilter",
                                     "||c.com^", "||c.com^$client=1.2.3.4,badfilter",
                                     "||d.com^$client=10.1.0.0/16|~10.1.2.3", "||d.com^$client=~10.1.2.3|10.1.9.9/16,badfilter"]), &[]);
        assert!(!t.client.contains_key("a.com")); assert!(t.client.contains_key("b.com"));
        assert!(t.block.contains_key("c.com")); assert!(!t.client.contains_key("d.com"));
        assert_eq!(n.badfiltered, 2);
    }

    #[test] #[ignore]
    fn real_inputs_measure() {
        // Directory of real list copies named <id>.txt; not shipped. Unset: nothing to measure.
        let Ok(dir) = std::env::var("DNSDOH_FILTER_FIXTURES") else { return };
        let mut all = vec![];
        for id in [1u64, 1707690930, 1764884031, 1779541509] {
            let text = std::fs::read_to_string(format!("{dir}/{id}.txt")).unwrap();
            for l in text.lines() { if let Parsed::Rule(r) = parse_line(l, Source::List(id)) { all.push(r); } }
        }
        let (t, n) = resolve(all, &[]);
        println!("block={} allow={} exact={} nx={} pattern_keys={} open_keys={} scan={} ips={} pruned={} badfiltered={} conflicts={:?}",
            t.block.len(), t.allow.len(), t.allow_exact.len(), t.block_nx.len(), t.pattern.len(), t.pattern_open.len(), t.scan.len(), t.ip_block.len(), n.pruned_allows, n.badfiltered, n.conflicts);
        let mut classes: BTreeMap<&str, usize> = BTreeMap::new();
        for (c, _) in &n.unsupported { *classes.entry(c).or_default() += 1; }
        println!("unsupported: {classes:?}");
        for class in classes.keys() {
            println!("--- examples for {class:?} ---");
            for (c, r) in n.unsupported.iter().filter(|(c, _)| c == class).take(5) { println!("{c}: {r}"); }
        }
    }
}
