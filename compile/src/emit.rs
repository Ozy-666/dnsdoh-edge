//! Tables → LMDB rows.
use crate::resolve::{Entry, Tables};

pub const CANARY: &str = "canary.dnsdoh-filter.invalid";

/// Lowercased DNS wire format incl. the terminating zero (dnsdist-kvs.cc:60,73).
pub fn wire(name: &str) -> Option<Vec<u8>> {
    let mut out = vec![];
    for l in name.split('.').filter(|l| !l.is_empty()) {
        if l.len() > 63 { return None; }
        out.push(l.len() as u8);
        out.extend(l.to_ascii_lowercase().bytes());
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

fn lines(es: &[Entry]) -> Vec<u8> { es.iter().map(Entry::line).collect::<Vec<_>>().join("\n").into_bytes() }

/// FNV-1a, 64 bit.
fn fnv1a64(b: &[u8]) -> u64 { b.iter().fold(0xcbf29ce484222325, |h, &x| (h ^ x as u64).wrapping_mul(0x100000001b3)) }

/// Dotted name from a wire-format key (inverse of `wire`); None if malformed.
fn unwire(w: &[u8]) -> Option<String> {
    let (mut i, mut labels) = (0, vec![]);
    while i < w.len() && w[i] != 0 {
        let l = w[i] as usize;
        labels.push(std::str::from_utf8(w.get(i + 1..i + 1 + l)?).ok()?);
        i += 1 + l;
    }
    (i + 1 == w.len()).then(|| labels.join("."))
}

/// `#pf` and `#gen`: every pattern row, for the per-thread pattern stage to hold in
/// memory (dnsdist/conf/modules/patterns_thread.lua). `#pf` = `pf3\t<gen>`, then one record per
/// row, `\x1e<kind><key>\x1d<value>`: kind `t` = a `pattern` row (key dotted), `o` = a
/// `pattern_open` label-run row, `s` = `*`, `a` = `**` (key empty for both); values never contain
/// 0x1d/0x1e. `#gen` = `<gen>`, a digest of the records: dnsdist compares it with the rows it
/// holds (at most once a second per thread) and reloads `#pf` when it differs. Derived from the
/// rows as written, in the same txn — by the compiler and by `put` (tests), so both keep it true.
pub fn thread_rows(pattern: &Rows, open: &Rows) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut body = vec![];
    let mut rec = |kind: u8, k: &[u8], v: &[u8]| -> Result<(), String> {
        if v.iter().chain(k).any(|&b| b == 0x1d || b == 0x1e) { return Err("pattern row contains 0x1d/0x1e".into()); }
        body.push(0x1e); body.push(kind); body.extend_from_slice(k); body.push(0x1d); body.extend_from_slice(v);
        Ok(())
    };
    for (k, v) in pattern { rec(b't', unwire(k).ok_or("pattern key is not a wire name")?.as_bytes(), v)?; }
    for (k, v) in open {
        match k.as_slice() {
            b"*" => rec(b's', b"", v)?,
            b"**" => rec(b'a', b"", v)?,
            k if k.starts_with(b"#") => {}
            k => rec(b'o', k, v)?,
        }
    }
    let gen = format!("{:016x}-{}", fnv1a64(&body), body.len());
    let mut pf = format!("pf3\t{gen}").into_bytes();
    pf.extend(body);
    Ok((pf, gen.into_bytes()))
}

/// `put` (tests): after a write to `pattern` or `pattern_open`, the `#pf`/`#gen` rows for the
/// tables as they now are.
pub fn derive_thread_rows(table: &str, rows: &dyn Fn(&str) -> Result<Rows, String>) -> Result<Vec<(&'static str, Vec<u8>, Vec<u8>)>, String> {
    if table != "pattern" && table != "pattern_open" { return Ok(vec![]); }
    let (pf, gen) = thread_rows(&rows("pattern")?, &rows("pattern_open")?)?;
    Ok(vec![("pattern_open", b"#pf".to_vec(), pf), ("pattern_open", b"#gen".to_vec(), gen)])
}

pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

pub fn rows(t: &Tables) -> (Vec<(&'static str, Rows)>, usize) {
    let mut skipped = 0;
    let mut named = |pairs: Vec<(&String, Vec<u8>)>| -> Rows {
        pairs.into_iter().filter_map(|(k, v)| match wire(k) { Some(w) => Some((w, v)), None => { skipped += 1; None } }).collect()
    };
    // A closure here would infer one concrete lifetime from its first call site and reject the
    // second (distinct-lifetime) call; a fn item elides per-call like any other function.
    fn plain(m: &std::collections::BTreeMap<String, (u8, String)>) -> Vec<(&String, Vec<u8>)> {
        m.iter().map(|(k, v)| (k, v.1.clone().into_bytes())).collect()
    }
    let allow_exact = named(plain(&t.allow_exact));
    let allow = named(plain(&t.allow));
    let mut block = named(plain(&t.block));
    block.push((wire(CANARY).unwrap(), b"CANARY".to_vec()));
    let block_nx = named(t.block_nx.iter().map(|(k, v)| (k, v.clone().into_bytes())).collect());
    let pattern = named(t.pattern.iter().map(|(k, v)| (k, lines(v))).collect());
    let rewrite = named(t.rewrite.iter().map(|(k, v)| (k, v.clone().into_bytes())).collect());
    let mut open: Rows = t.pattern_open.iter().map(|(k, v)| (k.clone().into_bytes(), lines(v))).collect();
    open.push((b"*".to_vec(), lines(&t.scan)));
    open.push((b"**".to_vec(), lines(&t.all_patterns)));
    open.push((b"#maxrun".to_vec(), t.max_run.to_string().into_bytes()));
    let (pf, gen) = thread_rows(&pattern, &open).expect("compiled pattern rows");
    open.push((b"#pf".to_vec(), pf));
    open.push((b"#gen".to_vec(), gen));
    let client = named(t.client.iter().map(|(k, v)| (k, v.iter().map(|e| e.line()).collect::<Vec<_>>().join("\n").into_bytes())).collect());
    let ip: Rows = t.ip_block.iter().map(|(k, v)| (k.to_vec(), v.clone().into_bytes())).collect();
    (vec![("allow_exact", allow_exact), ("allow", allow), ("block", block), ("block_nx", block_nx),
          ("pattern", pattern), ("pattern_open", open), ("ip_block", ip), ("rewrite", rewrite), ("client", client)], skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn thread_rows_blob() {
        use crate::rule::{parse_line, Parsed, Source};
        let rs = ["||an.yandex.", "-ads1.", "||ad-host-*.aliyuncs.com^"].iter().enumerate()
            .filter_map(|(i, l)| match parse_line(l, Source::User(i + 1)) { Parsed::Rule(r) => Some(r), _ => None }).collect();
        let (t, _) = crate::resolve::resolve(rs, &[]);
        let (rows0, _) = rows(&t);
        let get = |n: &str| rows0.iter().find(|(x, _)| *x == n).unwrap().1.clone();
        let open = get("pattern_open");
        let row = |k: &[u8]| String::from_utf8(open.iter().find(|(x, _)| x == k).unwrap().1.clone()).unwrap();
        let s = |v: Vec<u8>| String::from_utf8(v).unwrap();
        let body = format!("\x1etaliyuncs.com\x1d{}\x1eoan.yandex\x1d{}\x1es\x1d{}\x1ea\x1d{}",
            s(lines(&t.pattern["aliyuncs.com"])), s(lines(&t.pattern_open["an.yandex"])), s(lines(&t.scan)), s(lines(&t.all_patterns)));
        let want_gen = format!("{:016x}-{}", fnv1a64(body.as_bytes()), body.len());
        assert_eq!(row(b"#gen"), want_gen);
        assert_eq!(row(b"#pf"), format!("pf3\t{want_gen}{body}"));
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);   // published FNV-1a 64 test vector
        // put (tests) derives the same rows from the tables as stored.
        let d = derive_thread_rows("pattern", &|n: &str| Ok(get(n))).unwrap();
        assert_eq!(d[0].2, row(b"#pf").into_bytes());
        assert_eq!(d[1].2, want_gen.clone().into_bytes());
        assert!(derive_thread_rows("block", &|n: &str| Ok(get(n))).unwrap().is_empty());
        let (t2, _) = crate::resolve::resolve(vec![], &[]);
        let (r2, _) = rows(&t2);
        let g2 = r2.iter().find(|(x, _)| *x == "pattern_open").unwrap().1.iter().find(|(k, _)| k == b"#gen").unwrap().1.clone();
        assert_ne!(g2, want_gen.into_bytes());   // a different pattern set, a different #gen
        assert_eq!(unwire(&wire("a.bc").unwrap()).unwrap(), "a.bc");
        assert!(unwire(b"\x05ab\x00").is_none());
    }
    #[test] fn wire_format() {
        assert_eq!(wire("ab.c").unwrap(), b"\x02ab\x01c\x00".to_vec());
        assert!(wire(&"a".repeat(64)).is_none());
    }
    #[test] fn client_table_value() {
        use crate::resolve::ClientEntry;
        let n = |v: &[&str]| v.iter().map(|s| s.parse::<crate::rule::IpNet>().unwrap()).collect();
        let mut t = Tables::default();
        let (rows0, _) = rows(&t);
        assert!(rows0.iter().any(|(name, r)| *name == "client" && r.is_empty()), "client table always emitted");
        t.client.insert("tv.example".into(), vec![
            ClientEntry { level: 3, value: "U1!".into(), permit: n(&["10.0.0.0/8", "127.0.0.1/32"]), deny: vec![] },
            ClientEntry { level: 0, value: "U2".into(), permit: vec![], deny: n(&["192.0.2.1/32", "2001:db8::/32"]) },
        ]);
        let (rows, _) = rows(&t);
        let client = &rows.iter().find(|(name, _)| *name == "client").unwrap().1;
        assert_eq!(client, &vec![(wire("tv.example").unwrap(),
            b"3\tU1!\t10.0.0.0/8,127.0.0.1/32\t\nnx\tU2\t\t192.0.2.1/32,2001:db8::/32".to_vec())]);
    }
}
