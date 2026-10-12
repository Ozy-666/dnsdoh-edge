//! `/etc/dnsdoh.art/rewrites.conf` : `name A ipv4   # comment`. Exact names.
pub fn parse_rewrites(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim_start_matches('\u{feff}').split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 { return Err(format!("rewrites.conf:{n}: expected `name A address`")); }
        let name = f[0].trim_end_matches('.').to_ascii_lowercase();
        if !crate::rule::is_plain_name(&name) || crate::rule::name_too_long(&name) { return Err(format!("rewrites.conf:{n}: bad name {:?}", f[0])); }
        if f[1] != "A" { return Err(format!("rewrites.conf:{n}: only type A is supported (AAAA answers are disabled)")); }
        let ip: std::net::Ipv4Addr = f[2].parse().map_err(|_| format!("rewrites.conf:{n}: bad IPv4 {:?}", f[2]))?;
        if !seen.insert(name.clone()) { return Err(format!("rewrites.conf:{n}: duplicate name {name}")); }
        out.push((name, ip.to_string()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn good() {
        let r = parse_rewrites("\u{feff}# name type answer\r\nA.example.net.  A 192.0.2.10   # first\r\n\nb.example.net A 192.0.2.11\n").unwrap();
        assert_eq!(r, vec![("a.example.net".into(), "192.0.2.10".into()), ("b.example.net".into(), "192.0.2.11".into())]);
    }
    #[test] fn crlf_bom_trailing() { assert_eq!(parse_rewrites("\u{feff}x.com A 1.2.3.4  \r\n").unwrap().len(), 1); }
    #[test] fn errors_name_the_line() {
        for (s, want) in [("a.com AAAA ::1", ":1: only type A"), ("a.com A 1.2.3", ":1: bad IPv4"), ("a.com A 1.1.1.1\na.com A 2.2.2.2", ":2: duplicate"), ("*.a.com A 1.1.1.1", ":1: bad name"), (&format!("{}.com A 1.1.1.1", "a".repeat(64)), ":1: bad name"), ("a.com A", ":1: expected")] {
            let e = parse_rewrites(s).unwrap_err(); assert!(e.contains(want), "{s}: {e}");
        }
    }
}
