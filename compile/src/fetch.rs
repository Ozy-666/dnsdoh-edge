//! Conditional GET via curl (ETag + If-Modified-Since, size cap, timeout).
//!
//! A fetch never touches the promoted `<id>.txt` / `<id>.etag` that the *next* conditional GET
//! reads from. It stages a good body as `<id>.new` and its ETag as `<id>.etag.new`; a failed or
//! partial transfer (protocol error, timeout, over the size cap, non-200/304) leaves no trace at
//! all — not `<id>.new`, not `<id>.etag.new`, and critically not `<id>.etag`, because
//! `--etag-save` writes its (possibly empty) file the moment curl starts, even on failure, and a
//! poisoned `<id>.etag` would make the next run's `--etag-compare` see a 304 forever. `promote`
//! (called only after a successful commit) is the one place `.new`/`.etag.new` become the
//! promoted copies; `discard` (any refusal, or --dry-run) is the one place they disappear without
//! being promoted. `load` is what `compile()` actually parses this run: the freshly staged
//! body if the current run fetched one (or a previous run staged one and was interrupted before
//! promoting or discarding it) and it passes `validate` (AGH's own list checks), else the last
//! promoted copy — a staged body that fails `validate`, or the caller's `check` (the per-list
//! safety valve), is discarded like a failed fetch.
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::config::ListCfg;

#[derive(Debug, PartialEq)]
pub enum Got { Fresh, NotModified, Stale(String) }

fn p(dir: &Path, id: u64, suffix: &str) -> PathBuf { dir.join(format!("{id}{suffix}")) }

/// After a successful commit: staged files (if any) become the promoted copies.
pub fn promote(l: &ListCfg, dir: &Path) -> Result<(), String> {
    let (new, etag_new) = (p(dir, l.id, ".new"), p(dir, l.id, ".etag.new"));
    if new.exists() { std::fs::rename(&new, p(dir, l.id, ".txt")).map_err(|e| e.to_string())?; }
    if etag_new.exists() { std::fs::rename(&etag_new, p(dir, l.id, ".etag")).map_err(|e| e.to_string())?; }
    Ok(())
}

/// On any refusal, or --dry-run: drop staged files. The promoted copies are never touched here.
pub fn discard(l: &ListCfg, dir: &Path) {
    let _ = std::fs::remove_file(p(dir, l.id, ".new"));
    let _ = std::fs::remove_file(p(dir, l.id, ".etag.new"));
}

/// AdGuard Home's own checks on a downloaded rule list, mirrored exactly (AGH
/// internal/filtering/rulelist/parser.go, read-only reference tree), plus UTF-8, which AGH does
/// not need but `compile()` parses text. AGH rejects such a body and keeps the old list; so do we.
///
/// ```go
/// trimmed := bytes.TrimSpace(line)
/// if p.written == 0 && isHTMLLine(trimmed) {
/// 	return 0, ErrHTML
/// }
/// ...
/// return hasPrefixFold(line, []byte("<html")) || hasPrefixFold(line, []byte("<!doctype"))
/// ...
/// if len(line) == 0 || line[0] == '#' || line[0] == '!' {
/// 	return -1, false
/// }
/// badIdx = slices.IndexFunc(line, likelyBinary)
/// ...
/// return (b < ' ' || b == 0x7f) && b != '\n' && b != '\r' && b != '\t'
/// ```
///
/// `p.written == 0` holds until the first rule line has been written, so the HTML check applies
/// to every line up to and including the first rule line (comments and blank lines before it
/// included). Comment (`#`, `!`) and empty lines are never checked for binary characters (the
/// title-scanning variant `parseLineTitle` skips the same lines). Lines are split as
/// `bufio.ScanLines` splits them (`\n`, one trailing `\r` dropped) = `str::lines`; `TrimSpace`
/// (Unicode White_Space) = `str::trim`. The returned reason starts with the check's name.
pub fn validate(body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body).map_err(|e| format!("invalid UTF-8 at byte {}", e.valid_up_to()))?;
    let prefix_fold = |l: &str, p: &str| l.len() >= p.len() && l.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    let mut written = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if !written && (prefix_fold(t, "<html") || prefix_fold(t, "<!doctype")) {
            return Err(format!("html: line {} starts with <html or <!doctype", i + 1));
        }
        if t.is_empty() || t.starts_with('#') || t.starts_with('!') { continue; }
        if let Some(j) = t.bytes().position(|b| (b < b' ' || b == 0x7f) && b != b'\n' && b != b'\r' && b != b'\t') {
            return Err(format!("binary character 0x{:02x} at line {} (likely not a rule list)", t.as_bytes()[j], i + 1));
        }
        written = true;
    }
    Ok(())
}

/// `<id>.new` exists: this run (or an interrupted earlier one) staged a body.
pub fn staged(l: &ListCfg, dir: &Path) -> bool { p(dir, l.id, ".new").exists() }

/// The promoted copy (`<id>.txt`, the list as of the last commit), checked like `load` checks
/// it; `None` when there is none yet (first run for this list). Per-list valve baseline.
pub fn promoted_text(l: &ListCfg, dir: &Path) -> Result<Option<String>, String> {
    let cur = p(dir, l.id, ".txt");
    if !cur.exists() { return Ok(None); }
    let b = std::fs::read(&cur).map_err(|e| format!("no good copy of list {}: {}: {e}", l.id, cur.display()))?;
    validate(&b).map_err(|e| format!("no good copy of list {}: {}: {e}", l.id, cur.display()))?;
    Ok(Some(String::from_utf8(b).expect("validated as UTF-8")))
}

/// The text `compile()` parses for list `l` this run, and the source to report for it.
/// A staged body (`<id>.new`: fetched this run, or left by an interrupted run) is used only if it
/// passes `validate`, then `check` (the per-list valve); otherwise it is handled exactly like a failed fetch: the staged body and
/// ETag are discarded, the last good copy is used and the source becomes `Stale(<reason>)`.
/// The last good copy (`<id>.txt`) must itself pass `validate`, or the compile refuses naming
/// the list and the file.
pub fn load(l: &ListCfg, dir: &Path, got: Got, check: impl Fn(&str) -> Result<(), String>) -> Result<(String, Got), String> {
    let (new, cur) = (p(dir, l.id, ".new"), p(dir, l.id, ".txt"));
    let mut got = got;
    if new.exists() {
        let checked = std::fs::read(&new).map_err(|e| format!("unreadable: {e}"))
            .and_then(|b| validate(&b).map(|()| String::from_utf8(b).expect("validated as UTF-8")))
            .and_then(|t| check(&t).map(|()| t));
        match checked {
            Ok(t) => return Ok((t, got)),
            Err(why) => { discard(l, dir); got = Got::Stale(why); }
        }
    }
    if !cur.exists() {
        let why = match &got { Got::Stale(w) => w.clone(), _ => "missing".into() };
        return Err(format!("no good copy of list {} ({why})", l.id));
    }
    let b = std::fs::read(&cur).map_err(|e| format!("no good copy of list {}: {}: {e}", l.id, cur.display()))?;
    validate(&b).map_err(|e| format!("no good copy of list {}: {}: {e}", l.id, cur.display()))?;
    Ok((String::from_utf8(b).expect("validated as UTF-8"), got))
}

/// A list URL is fetched only from a public address. The UI can add a
/// list by URL; a name that resolves to loopback, CGNAT, a LAN or a reserved range would
/// turn the compiler into a probe of internal services. Checked on every fetch, for every list.
pub fn is_public(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr::{V4, V6};
    match ip {
        V4(a) => {
            let o = a.octets();
            !(a.is_unspecified() || a.is_loopback() || a.is_private() || a.is_link_local() || a.is_broadcast()
              || a.is_documentation() || a.is_multicast()
              || o[0] == 0                                   // 0.0.0.0/8
              || (o[0] == 100 && (o[1] & 0xc0) == 64)         // 100.64.0.0/10 (CGNAT)
              || (o[0] == 192 && o[1] == 0 && o[2] == 0)      // 192.0.0.0/24
              || (o[0] == 198 && (o[1] & 0xfe) == 18)         // 198.18.0.0/15
              || o[0] >= 240)                                 // 240.0.0.0/4
        }
        V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() { return is_public(V4(v4)); }
            let s = a.segments();
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast()
              || (s[0] & 0xfe00) == 0xfc00                    // fc00::/7
              || (s[0] & 0xffc0) == 0xfe80                    // fe80::/10
              || (s[0] == 0x2001 && s[1] == 0x0db8)           // 2001:db8::/32
              || (s[0] == 0x0064 && s[1] == 0xff9b))          // 64:ff9b::/96 NAT64
        }
    }
}

/// `host:port:addr` for curl `--resolve`: the URL's host resolved once, every address public, the
/// first IPv4 (else first) address pinned. Refuses non-https, userinfo, and unresolvable hosts.
pub fn pin(url: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs;
    let rest = url.strip_prefix("https://").ok_or("list URL is not https")?;
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    if auth.contains('@') { return Err("list URL has userinfo".into()); }
    let (host, port) = match auth.strip_prefix('[') {
        Some(v6) => { let (h, p) = v6.split_once(']').ok_or("bad IPv6 literal")?; (h, p.strip_prefix(':')) }
        None => match auth.rsplit_once(':') { Some((h, p)) => (h, Some(p)), None => (auth, None) },
    };
    let port: u16 = match port { Some(p) => p.parse().map_err(|_| "bad port in list URL")?, None => 443 };
    if host.is_empty() { return Err("list URL has no host".into()); }
    let addrs: Vec<std::net::IpAddr> = (host, port).to_socket_addrs()
        .map_err(|e| format!("cannot resolve list host {host}: {e}"))?.map(|s| s.ip()).collect();
    if addrs.is_empty() { return Err(format!("cannot resolve list host {host}: no address")); }
    // Report an IPv4 offender first so the message does not depend on resolver ordering.
    if let Some(bad) = addrs.iter().filter(|a| a.is_ipv4()).chain(addrs.iter()).find(|a| !is_public(**a)) {
        return Err(format!("list host {host} resolves to a non-public address {bad}; refused"));
    }
    let a = addrs.iter().find(|a| a.is_ipv4()).unwrap_or(&addrs[0]);
    Ok(match a { std::net::IpAddr::V6(v6) => format!("{host}:{port}:[{v6}]"), v4 => format!("{host}:{port}:{v4}") })
}

/// Fixed curl arguments up to (and including) `-o`. `-g` (--globoff) turns off curl's own `[]{}`
/// URL globbing, so a URL cannot expand into many requests.
fn curl_base_args(timeout: u64, max: u64) -> Vec<String> {
    ["-sS", "-g", "--fail", "--proto", "=https", "-R", "--max-time", &timeout.to_string(), "--max-filesize", &max.to_string(), "-w", "%{http_code}", "-o"]
        .iter().map(|s| s.to_string()).collect()
}

/// curl's whole argv for one fetch: fixed arguments, `-o <part>`, the ETag scratch file, the
/// pinned `--resolve` (the address `pin` checked is the one curl connects to), the conditional-GET
/// pair when a promoted copy exists (`cond` = (`<id>.txt`, `<id>.etag` if present)), the URL last.
fn curl_args(timeout: u64, max: u64, part: &Path, part_etag: &Path, resolve: &str,
             cond: Option<(&Path, Option<&Path>)>, url: &str) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = curl_base_args(timeout, max).into_iter().map(Into::into).collect();
    a.push(part.into());
    a.push("--etag-save".into()); a.push(part_etag.into());
    a.push("--resolve".into()); a.push(resolve.into());
    if let Some((cur, etag)) = cond {
        a.push("-z".into()); a.push(cur.into());
        if let Some(e) = etag { a.push("--etag-compare".into()); a.push(e.into()); }
    }
    a.push(url.into());
    a
}

pub fn fetch(l: &ListCfg, dir: &Path, timeout: u64, max: u64) -> Result<Got, String> {
    let cur = p(dir, l.id, ".txt");
    let etag = p(dir, l.id, ".etag");
    let new = p(dir, l.id, ".new");
    let etag_new = p(dir, l.id, ".etag.new");
    let part = p(dir, l.id, ".part");
    // Scratch destination for --etag-save: curl (re)writes this the instant it starts, even for
    // a transfer that then fails, times out or is cut off — so it must never be `etag` or
    // `etag_new` directly (see module doc).
    let part_etag = p(dir, l.id, ".etag.part");
    let _ = std::fs::remove_file(&part);
    let _ = std::fs::remove_file(&part_etag);
    // A refused or unresolvable host is a failed fetch like any network failure: Stale when a good
    // copy exists, else an error naming the list.
    let resolve = match pin(&l.url) {
        Ok(r) => r,
        Err(why) => return if cur.exists() { Ok(Got::Stale(why)) } else { Err(format!("no good copy of list {} ({why})", l.id)) },
    };
    let cond = if cur.exists() { Some((cur.as_path(), etag.exists().then_some(etag.as_path()))) } else { None };
    let out = Command::new("curl").args(curl_args(timeout, max, &part, &part_etag, &resolve, cond, &l.url))
        .output().map_err(|e| format!("curl: {e}"))?;
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let len = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let got = match (out.status.success(), code.as_str()) {
        (true, "304") => Ok(Got::NotModified),
        (true, "200") if len > 0 => {
            std::fs::rename(&part, &new).map_err(|e| e.to_string())?;
            // Best-effort: a good body is never discarded for want of an etag; a missing
            // `.etag.new` just means the next run does a full GET instead of a conditional one.
            let _ = std::fs::rename(&part_etag, &etag_new);
            Ok(Got::Fresh)
        }
        _ => {
            let why = format!("HTTP {code} {}", String::from_utf8_lossy(&out.stderr).trim());
            if cur.exists() { Ok(Got::Stale(why)) } else { Err(format!("no good copy of list {} ({why})", l.id)) }
        }
    };
    let _ = std::fs::remove_file(&part);
    let _ = std::fs::remove_file(&part_etag);
    got
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("fetchtest-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    #[test]
    fn curl_args_turn_globbing_off() {
        let a = curl_base_args(60, 1000);
        assert!(a.iter().any(|x| x == "-g"), "{a:?}");
        assert_eq!(a.last().map(String::as_str), Some("-o"));
    }
    #[test]
    fn curl_args_carry_resolve_part_and_url() {
        use std::ffi::OsString;
        let (part, pe) = (Path::new("/d/7.part"), Path::new("/d/7.etag.part"));
        let pinned = "lists.example:443:203.0.113.9";
        let url = "https://lists.example/l.txt";
        for cond in [None, Some((Path::new("/d/7.txt"), None)), Some((Path::new("/d/7.txt"), Some(Path::new("/d/7.etag"))))] {
            let a = curl_args(60, 1000, part, pe, pinned, cond, url);
            let i = a.iter().position(|x| x == "--resolve").unwrap_or_else(|| panic!("no --resolve in {a:?}"));
            assert_eq!(a.get(i + 1), Some(&OsString::from(pinned)), "{a:?}");
            let o = a.iter().position(|x| x == "-o").unwrap_or_else(|| panic!("no -o in {a:?}"));
            assert_eq!(a.get(o + 1), Some(&OsString::from(part)), "{a:?}");
            assert_eq!(a.last(), Some(&OsString::from(url)), "{a:?}");
            assert_eq!(a.iter().any(|x| x == "-z"), cond.is_some(), "{a:?}");
            assert_eq!(a.iter().any(|x| x == "--etag-compare"), matches!(cond, Some((_, Some(_)))), "{a:?}");
        }
    }
    fn cfg(id: u64, url: &str) -> ListCfg { ListCfg { id, name: "t".into(), url: url.into(), enabled: true } }
    #[test] fn is_public_table() {
        use std::net::IpAddr;
        for a in ["1.1.1.1", "9.9.9.10", "2606:4700::1111"] {
            assert!(is_public(a.parse::<IpAddr>().unwrap()), "{a}");
        }
        for a in ["0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                  "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
                  "224.0.0.1", "240.0.0.1", "255.255.255.255",
                  "::", "::1", "fc00::1", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"] {
            assert!(!is_public(a.parse::<IpAddr>().unwrap()), "{a}");
        }
    }
    #[test] fn pin_refuses_local_names() {
        let e = pin("https://localhost/list.txt").unwrap_err();
        assert!(e.contains("non-public address 127.0.0.1"), "{e}");
        assert!(pin("https://localhost:8443/x").unwrap_err().contains("non-public"));
        assert!(pin("https://user@localhost/x").is_err());
        assert!(pin("http://localhost/x").is_err());
        assert!(pin("https://no-such-host.invalid/x").unwrap_err().contains("resolve"));
    }
    #[test] fn pin_formats_resolve_value() {
        // A literal public address resolves to itself without DNS.
        assert_eq!(pin("https://1.1.1.1/x").unwrap(), "1.1.1.1:443:1.1.1.1");
        assert_eq!(pin("https://1.1.1.1:8443/x?y#z").unwrap(), "1.1.1.1:8443:1.1.1.1");
    }
    #[test] fn refused_host_is_stale_with_a_good_copy_and_an_error_without() {
        let dir = tmp();
        let l = cfg(9003, "https://localhost/x");
        let e = fetch(&l, &dir, 5, 1 << 20).unwrap_err();
        assert!(e.starts_with("no good copy of list 9003") && e.contains("non-public"), "{e}");
        std::fs::write(p(&dir, 9003, ".txt"), b"GOOD OLD COPY").unwrap();
        let got = fetch(&l, &dir, 5, 1 << 20).unwrap();
        assert!(matches!(&got, Got::Stale(w) if w.contains("non-public")), "{got:?}");
        assert_eq!(std::fs::read(p(&dir, 9003, ".txt")).unwrap(), b"GOOD OLD COPY");
        assert!(!p(&dir, 9003, ".new").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Deterministic, network-free failure: `--proto '=https'` rejects a plain-http URL before
    // any connection is attempted (curl exit 1, "Protocol ... is disabled").
    const BAD_SCHEME: &str = "http://example.invalid/x";

    #[test]
    fn failed_fetch_with_no_prior_copy_errors_and_leaves_no_files() {
        let dir = tmp();
        let l = cfg(9001, BAD_SCHEME);
        let e = fetch(&l, &dir, 5, 1 << 20).unwrap_err();
        assert!(e.starts_with("no good copy of list 9001"), "{e}");
        for suf in [".txt", ".etag", ".new", ".etag.new", ".part", ".etag.part"] {
            assert!(!p(&dir, 9001, suf).exists(), "{suf} should not exist after a failed fetch with no prior copy");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_fetch_with_prior_copy_is_stale_and_does_not_touch_the_promoted_files() {
        let dir = tmp();
        let l = cfg(9002, BAD_SCHEME);
        std::fs::write(p(&dir, 9002, ".txt"), b"GOOD OLD COPY").unwrap();
        std::fs::write(p(&dir, 9002, ".etag"), b"\"old-etag\"").unwrap();
        let got = fetch(&l, &dir, 5, 1 << 20).unwrap();
        assert!(matches!(got, Got::Stale(_)), "{got:?}");
        assert_eq!(std::fs::read(p(&dir, 9002, ".txt")).unwrap(), b"GOOD OLD COPY");
        assert_eq!(std::fs::read(p(&dir, 9002, ".etag")).unwrap(), b"\"old-etag\"");
        assert!(!p(&dir, 9002, ".new").exists(), "a failed fetch must not stage a .new body");
        assert!(!p(&dir, 9002, ".etag.new").exists(), "a failed fetch must not stage a .etag.new — this is the poisoned-etag bug");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn promote_moves_staged_files_over_the_promoted_copies() {
        let dir = tmp();
        let l = cfg(9003, BAD_SCHEME);
        std::fs::write(p(&dir, 9003, ".txt"), b"old").unwrap();
        std::fs::write(p(&dir, 9003, ".etag"), b"\"old\"").unwrap();
        std::fs::write(p(&dir, 9003, ".new"), b"new").unwrap();
        std::fs::write(p(&dir, 9003, ".etag.new"), b"\"new\"").unwrap();
        promote(&l, &dir).unwrap();
        assert_eq!(std::fs::read(p(&dir, 9003, ".txt")).unwrap(), b"new");
        assert_eq!(std::fs::read(p(&dir, 9003, ".etag")).unwrap(), b"\"new\"");
        assert!(!p(&dir, 9003, ".new").exists());
        assert!(!p(&dir, 9003, ".etag.new").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discard_drops_staged_files_and_never_touches_the_promoted_copies() {
        let dir = tmp();
        let l = cfg(9004, BAD_SCHEME);
        std::fs::write(p(&dir, 9004, ".txt"), b"keep-me").unwrap();
        std::fs::write(p(&dir, 9004, ".etag"), b"\"keep-me\"").unwrap();
        std::fs::write(p(&dir, 9004, ".new"), b"garbage").unwrap();
        std::fs::write(p(&dir, 9004, ".etag.new"), b"\"garbage\"").unwrap();
        discard(&l, &dir);
        assert!(!p(&dir, 9004, ".new").exists());
        assert!(!p(&dir, 9004, ".etag.new").exists());
        assert_eq!(std::fs::read(p(&dir, 9004, ".txt")).unwrap(), b"keep-me");
        assert_eq!(std::fs::read(p(&dir, 9004, ".etag")).unwrap(), b"\"keep-me\"");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_mirrors_agh_rulelist_parser() {
        // Accepted: rules, comments, a title, CR/LF endings, tabs, blank lines, non-ASCII text.
        for ok in ["||a.example^\n", "! Title: x\r\n# c\n\n||a.example^\t\r\n", "", "! only comments\n",
                   "||a.example^\n<html>\n", "! caf\u{e9}\n||xn--caf-dma.example^\n", "#\x01 comment\n!\x02\n||a^\n"] {
            assert_eq!(validate(ok.as_bytes()), Ok(()), "{ok:?}");
        }
        // HTML: any line up to the first rule line, case-insensitive, after trimming.
        for html in ["<!DOCTYPE html>\n<html>", "<html>404</html>", "! Title: x\n\n  <HTML lang=en>\n", "\u{a0}<!doctype html>"] {
            let e = validate(html.as_bytes()).unwrap_err(); assert!(e.starts_with("html: "), "{html:?}: {e}");
        }
        // Binary: control characters other than \t \r \n, and DEL, in a rule line.
        for (bin, b) in [("||a^\x01\n", 0x01u8), ("x\x7f", 0x7f), ("! t\n||ok^\n\x00\x00", 0x00), ("a\x0bb", 0x0b)] {
            let e = validate(bin.as_bytes()).unwrap_err();
            assert!(e.starts_with(&format!("binary character 0x{b:02x}")), "{bin:?}: {e}");
        }
        let e = validate(b"||ok.example^\n||caf\xe9.example^\n").unwrap_err();
        assert_eq!(e, "invalid UTF-8 at byte 19");
    }

    #[test]
    fn load_treats_a_bad_staged_body_like_a_failed_fetch() {
        let dir = tmp();
        let l = cfg(9006, BAD_SCHEME);
        std::fs::write(p(&dir, 9006, ".txt"), b"||good.example^\n").unwrap();
        std::fs::write(p(&dir, 9006, ".new"), b"<!doctype html>\nSorry\n").unwrap();
        std::fs::write(p(&dir, 9006, ".etag.new"), b"\"html\"").unwrap();
        let (text, got) = load(&l, &dir, Got::Fresh, |_| Ok(())).unwrap();
        assert_eq!(text, "||good.example^\n");
        assert!(matches!(&got, Got::Stale(w) if w.starts_with("html: ")), "{got:?}");
        assert!(!p(&dir, 9006, ".new").exists() && !p(&dir, 9006, ".etag.new").exists());
        // A good staged body is used as is.
        std::fs::write(p(&dir, 9006, ".new"), b"||new.example^\n").unwrap();
        assert_eq!(load(&l, &dir, Got::Fresh, |_| Ok(())).unwrap(), ("||new.example^\n".to_string(), Got::Fresh));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_refuses_naming_the_list_without_a_good_copy() {
        let dir = tmp();
        let l = cfg(9007, BAD_SCHEME);
        std::fs::write(p(&dir, 9007, ".new"), b"\xff\n").unwrap();
        let e = load(&l, &dir, Got::Fresh, |_| Ok(())).unwrap_err();
        assert_eq!(e, "no good copy of list 9007 (invalid UTF-8 at byte 0)");
        std::fs::write(p(&dir, 9007, ".txt"), b"||a^\n\xff\n").unwrap();
        let e = load(&l, &dir, Got::NotModified, |_| Ok(())).unwrap_err();
        assert_eq!(e, format!("no good copy of list 9007: {}: invalid UTF-8 at byte 5", p(&dir, 9007, ".txt").display()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_check_failure_falls_back_like_a_bad_body() {
        let dir = tmp();
        let l = cfg(9010, BAD_SCHEME);
        std::fs::write(p(&dir, 9010, ".txt"), b"||old.example^\n").unwrap();
        std::fs::write(p(&dir, 9010, ".new"), b"||new.example^\n").unwrap();
        std::fs::write(p(&dir, 9010, ".etag.new"), b"\"new\"").unwrap();
        let (text, got) = load(&l, &dir, Got::Fresh, |_| Err("valve 1 < 2 x (1 - 0.25)".into())).unwrap();
        assert_eq!(text, "||old.example^\n");
        assert!(matches!(&got, Got::Stale(w) if w == "valve 1 < 2 x (1 - 0.25)"), "{got:?}");
        assert!(!p(&dir, 9010, ".new").exists(), "staged body must be discarded");
        assert!(!p(&dir, 9010, ".etag.new").exists(), "staged ETag must be discarded (else 304 forever)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_check_ok_uses_the_staged_body() {
        let dir = tmp();
        let l = cfg(9011, BAD_SCHEME);
        std::fs::write(p(&dir, 9011, ".txt"), b"||old.example^\n").unwrap();
        std::fs::write(p(&dir, 9011, ".new"), b"||new.example^\n").unwrap();
        let (text, got) = load(&l, &dir, Got::Fresh, |t| { assert_eq!(t, "||new.example^\n"); Ok(()) }).unwrap();
        assert_eq!(text, "||new.example^\n");
        assert!(matches!(got, Got::Fresh), "{got:?}");
        assert!(p(&dir, 9011, ".new").exists(), "an accepted staged body stays staged until promote");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_check_not_called_without_a_staged_body() {
        let dir = tmp();
        let l = cfg(9012, BAD_SCHEME);
        std::fs::write(p(&dir, 9012, ".txt"), b"||old.example^\n").unwrap();
        let (text, _) = load(&l, &dir, Got::NotModified, |_| panic!("check must not run on the promoted copy")).unwrap();
        assert_eq!(text, "||old.example^\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn promoted_text_missing_is_none_and_corrupt_is_named() {
        let dir = tmp();
        let l = cfg(9013, BAD_SCHEME);
        assert_eq!(promoted_text(&l, &dir).unwrap(), None);
        assert!(!staged(&l, &dir));
        std::fs::write(p(&dir, 9013, ".new"), b"x").unwrap();
        assert!(staged(&l, &dir));
        std::fs::write(p(&dir, 9013, ".txt"), b"||caf\xe9.example^\n").unwrap();
        let e = promoted_text(&l, &dir).unwrap_err();
        assert!(e.starts_with("no good copy of list 9013: ") && e.contains("9013.txt"), "{e}");
        std::fs::write(p(&dir, 9013, ".txt"), b"||ok.example^\n").unwrap();
        assert_eq!(promoted_text(&l, &dir).unwrap().as_deref(), Some("||ok.example^\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
