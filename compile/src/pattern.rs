//! AdGuard pattern → hostname matcher and lookup key.
//! urlfilter matches `||`, `://`, `http(s)://` patterns against "http://"+host and all others
//! against the host (rules/network.go:557-600); both reduce to hostname forms here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start { Any, Host, Domain }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End { Open, Sep, SepEnd, End }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pat { pub start: Start, pub body: String, pub end: End }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key { Tail(String), Open(String), Scan }

const HOST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_";
/// urlfilter RegexSeparator `([^ a-zA-Z0-9.%_-]|$)`, as a Lua class (the `|$` half is a variant).
const SEP: &str = "[^ %w%.%%_%-]";

impl Pat {
    /// Ok(None) = can never match a hostname (reported as such).
    pub fn parse(p: &str) -> Result<Option<Pat>, String> {
        let (start, rest) = if let Some(r) = p.strip_prefix("||") { (Start::Domain, r) }
            else if p.starts_with("https://") { return Ok(None); }
            else if let Some(r) = p.strip_prefix("http://") { (Start::Host, r) }
            else if let Some(r) = p.strip_prefix("://") { (Start::Host, r) }
            else if let Some(r) = p.strip_prefix('|') { (Start::Host, r) }
            else { (Start::Any, p) };
        let (end, body) = if let Some(b) = rest.strip_suffix("^|") { (End::SepEnd, b) }
            else if let Some(b) = rest.strip_suffix('|') { (End::End, b) }
            else if let Some(b) = rest.strip_suffix('^') { (End::Sep, b) }
            else { (End::Open, rest) };
        if body.bytes().all(|b| b == b'*') { return Err("matches everything".into()); }
        if body.contains('^') || body.contains('|') { return Err("separator or pipe inside the pattern".into()); }
        if !body.bytes().all(|b| b == b'*' || HOST_CHARS.contains(&b)) { return Ok(None); }
        Ok(Some(Pat { start, body: body.to_string(), end }))
    }

    fn lua_body(&self) -> String {
        let mut s = String::new();
        for c in self.body.chars() {
            match c { '*' => s.push_str(".-"), '.' | '-' => { s.push('%'); s.push(c) } c => s.push(c) }
        }
        s
    }

    /// OR of these Lua patterns == the urlfilter regex, on a lowercase hostname.
    pub fn lua_patterns(&self) -> Vec<String> {
        let body = self.lua_body();
        // `||` = ^(http|https|ws|wss)://([a-z0-9-_.]+\.)? on the URL (rules/regexp.go:48).
        let starts: &[&str] = match self.start { Start::Any => &[""], Start::Host => &["^"], Start::Domain => &["^", "^[a-z0-9_%.%-]+%."] };
        let ends: Vec<String> = match self.end {
            End::Open => vec![String::new()],
            End::End => vec!["$".into()],
            End::Sep => vec!["$".into(), SEP.into()],
            End::SepEnd => vec!["$".into(), format!("{SEP}$")],
        };
        let mut out = vec![];
        for s in starts { for e in &ends { out.push(format!("{s}{body}{e}")); } }
        out
    }

    /// A fixed ending of ≥ 2 full labels → C++ suffix prefilter (`pattern`);
    /// else the longest run of full labels (≥ 2, or 1 of ≥ 4 chars) → `pattern_open`; else scan.
    pub fn key(&self) -> Key {
        let chunks: Vec<&str> = self.body.split('*').collect();
        let last = chunks[chunks.len() - 1];
        if self.end != End::Open {
            if let Some(i) = last.find('.') {
                let tail = &last[i + 1..];
                if tail.contains('.') && tail.split('.').all(|l| !l.is_empty()) { return Key::Tail(tail.to_string()); }
            }
        }
        let mut best: Vec<&str> = vec![];
        for (ci, chunk) in chunks.iter().enumerate() {
            let labels: Vec<&str> = chunk.split('.').collect();
            let mut run: Vec<&str> = vec![];
            for (li, l) in labels.iter().enumerate() {
                let left = li > 0 || (ci == 0 && self.start != Start::Any);
                let right = li + 1 < labels.len() || (ci + 1 == chunks.len() && self.end != End::Open);
                if !l.is_empty() && left && right { run.push(l) } else { run.clear() }
                let longer = run.len() > best.len() || (run.len() == best.len() && run.join(".").len() > best.join(".").len());
                if !run.is_empty() && longer { best = run.clone(); }
            }
        }
        if best.len() >= 2 || (best.len() == 1 && best[0].len() >= 4) { Key::Open(best.join(".")) } else { Key::Scan }
    }

    /// Could this match a dotted IPv4 string (response side)?
    pub fn may_match_ip(&self) -> bool { self.body.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'*') }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pat(s: &str) -> Pat { Pat::parse(s).unwrap().unwrap() }
    #[test] fn starts_and_ends() {
        assert_eq!(pat("||a*.b.com^"), Pat { start: Start::Domain, body: "a*.b.com".into(), end: End::Sep });
        assert_eq!(pat("://jhf.ru^").start, Start::Host);
        assert_eq!(pat("http://x.ru").start, Start::Host);
        assert_eq!(pat("|piwik.").start, Start::Host);
        assert_eq!(pat("-ds.metric.gstatic.com^|").end, End::SepEnd);
        assert_eq!(pat(".stape.net"), Pat { start: Start::Any, body: ".stape.net".into(), end: End::Open });
        assert_eq!(Pat::parse("https://x.ru^"), Ok(None));
        assert_eq!(Pat::parse("example.com/ads"), Ok(None));
        assert!(Pat::parse("||").is_err());
        assert!(Pat::parse("a^b").is_err());
    }
    #[test] fn lua() {
        assert_eq!(pat("||an.yandex.").lua_patterns(), vec!["^an%.yandex%.", "^[a-z0-9_%.%-]+%.an%.yandex%."]);
        assert_eq!(pat("||a*.b.com^").lua_patterns(), vec![
            "^a.-%.b%.com$", "^a.-%.b%.com[^ %w%.%%_%-]",
            "^[a-z0-9_%.%-]+%.a.-%.b%.com$", "^[a-z0-9_%.%-]+%.a.-%.b%.com[^ %w%.%%_%-]"]);
        assert_eq!(pat("-ds.metric.gstatic.com^|").lua_patterns(), vec!["%-ds%.metric%.gstatic%.com$", "%-ds%.metric%.gstatic%.com[^ %w%.%%_%-]$"]);
    }
    #[test] fn keys() {
        assert_eq!(pat("||ad-host-backup-*.aliyuncs.com^").key(), Key::Tail("aliyuncs.com".into()));
        assert_eq!(pat(".bbelements.com^").key(), Key::Tail("bbelements.com".into()));
        assert_eq!(pat("-ds.metric.gstatic.com^|").key(), Key::Tail("metric.gstatic.com".into()));
        assert_eq!(pat("||an.yandex.").key(), Key::Open("an.yandex".into()));
        assert_eq!(pat("://jhf.ru^").key(), Key::Open("jhf.ru".into()));
        assert_eq!(pat("||direct-specific.com").key(), Key::Open("direct-specific".into()));
        assert_eq!(pat("||st-n.ads*-adnow.com^").key(), Key::Open("st-n".into()));
        assert_eq!(pat("||putrr*.com^").key(), Key::Scan);
        assert_eq!(pat("-ads1.").key(), Key::Scan);
    }
    #[test] fn ip_like() { assert!(pat("||194.63.143.*^").may_match_ip()); assert!(!pat("||a*.b.com^").may_match_ip()); }
}
