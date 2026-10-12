//! dnsdoh.art-compile — AdGuard lists + user rules + rewrites → one LMDB.
mod config;
mod emit;
mod fetch;
mod lmdb;
mod pattern;
mod report;
mod resolve;
mod rewrites;
mod rule;

use serde_json::json;
use std::io::BufRead;
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("patterns") => { patterns(); 0 }
        Some("put") | Some("get") => kv_cmd(&args).unwrap_or_else(|e| { eprintln!("{e}"); 1 }),
        _ => run(&args),
    };
    std::process::exit(code);
}

/// Rules in a list body, as `compile()` counts them for `status.lists[].rules` (per-list valve).
fn rule_count(text: &str, id: u64) -> usize {
    text.lines().filter(|l| matches!(rule::parse_line(l, rule::Source::List(id)), rule::Parsed::Rule(_))).count()
}

fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

/// tmp-write + rename in the same directory: never leaves a half-written last-commit.json.
/// `lists`: the enabled list ids of this commit (total-valve skip).
fn write_last_commit(path: &Path, block: u64, lists: &[u64]) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json!({"block": block, "time": now(), "lists": lists}).to_string()).map_err(|e| e.to_string())?;
    let r = std::fs::rename(&tmp, path).map_err(|e| e.to_string());
    if r.is_err() { let _ = std::fs::remove_file(&tmp); }
    r
}

/// Post-commit bookkeeping (last-commit.json, promoting fetched lists) can fail without the DB
/// commit itself being undone; record it as a warning, never as a refusal.
fn warn(status: &mut serde_json::Value, msg: String) {
    eprintln!("dnsdoh.art-compile: committed, but {msg}");
    let combined = match status.get("warning").and_then(|v| v.as_str()) {
        Some(prev) => format!("{prev}; {msg}"),
        None => msg,
    };
    status["warning"] = json!(combined);
}

fn run(args: &[String]) -> i32 {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let cfg_path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/dnsdoh.art/compile.toml"));
    let cfg = match config::load(&cfg_path) { Ok(c) => c, Err(e) => { eprintln!("dnsdoh.art-compile: {e}"); return 1; } };
    // One compile at a time: a second run would overwrite the first's status file and could
    // discard the staged body the first is about to promote. It refuses before touching any
    // state. The lock is held until exit; a leftover lock file is not a lock.
    let lock_path = cfg.state_dir.join("compile.lock");
    let _lock = match std::fs::create_dir_all(&cfg.state_dir)
        .and_then(|()| std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)) {
        Ok(f) => match f.try_lock() {
            Ok(()) => f,
            Err(std::fs::TryLockError::WouldBlock) => {
                eprintln!("dnsdoh.art-compile: another compile is running ({})", lock_path.display()); return 1;
            }
            Err(std::fs::TryLockError::Error(e)) => { eprintln!("dnsdoh.art-compile: {}: {e}", lock_path.display()); return 1; }
        },
        Err(e) => { eprintln!("dnsdoh.art-compile: {}: {e}", lock_path.display()); return 1; }
    };
    let mut status = json!({"time": now(), "committed": false, "reason": "", "lists": [], "dry_run": flag("--dry-run")});
    // `--accept-list <id>` only; a look-alike (`--accept-list=<id>`, `--accept-lists`) is passed
    // on NUL-marked so compile() refuses it rather than silently ignoring it (final review).
    let accept: Vec<String> = args.iter().enumerate().filter_map(|(i, a)| match a.as_str() {
        "--accept-list" => Some(args.get(i + 1).cloned().unwrap_or_default()),
        _ if a.starts_with("--accept-list") => Some(format!("\0{a}")),
        _ => None,
    }).collect();
    let result = compile(&cfg, flag("--offline"), flag("--dry-run"), &accept, &mut status);
    let lists_dir = cfg.state_dir.join("lists");
    let committed = status["committed"].as_bool().unwrap_or(false);
    if committed {
        // The DB is already committed at this point (never touch it again here). A
        // failure in the bookkeeping below is a warning, not a refusal — it must never flip the
        // exit code or make status["committed"] a lie.
        let last_path = cfg.state_dir.join("last-commit.json");
        let block = status["block_count"].as_u64().unwrap_or(0);
        if let Err(e) = write_last_commit(&last_path, block, &cfg.enabled_ids()) {
            warn(&mut status, format!("writing last-commit.json: {}: {e}", last_path.display()));
        }
        for l in cfg.enabled() {
            if let Err(e) = fetch::promote(l, &lists_dir) {
                warn(&mut status, format!("promoting list {}: {e}", l.id));
            }
        }
    } else {
        // Refused, or a clean --dry-run: any staged fetch this run must not survive to be
        // mistaken for a promoted copy next time.
        for l in cfg.enabled() { fetch::discard(l, &lists_dir); }
        // A refusal names file and line; the rule text in it is redacted (no client
        // addresses in compile-status.json or on stderr, which the journal writes to disk).
        if let Err(e) = &result { let e = report::redact_clients(e); status["reason"] = json!(e); eprintln!("dnsdoh.art-compile: refused: {e}"); }
    }
    if let Err(e) = report::write(&cfg.state_dir, &status) {
        // After a commit the DB is live: a status-file failure is a warning (exit 0), never a
        // refusal. Otherwise the run already failed or was a dry run.
        if committed { eprintln!("dnsdoh.art-compile: committed, but writing compile-status.json: {e}"); return 0; }
        eprintln!("dnsdoh.art-compile: status: {e}"); return 1;
    }
    if result.is_ok() { 0 } else { 1 }
}

fn compile(cfg: &config::Config, offline: bool, dry: bool, accept: &[String], status: &mut serde_json::Value) -> Result<(), String> {
    // --accept-list <id>: skip the per-list valve for these lists on this run only.
    // Anything that is not a configured list id refuses: a typo must not look like success.
    let mut accepted = vec![];
    for v in accept {
        if let Some(bad) = v.strip_prefix('\0') { return Err(format!("--accept-list: unknown argument '{bad}'")); }
        // The id exactly as compile.toml spells it: no "+", no leading zeros.
        match v.parse::<u64>().ok().filter(|id| id.to_string() == *v && cfg.enabled().any(|l| l.id == *id)) {
            Some(id) => accepted.push(id),
            None => return Err(format!("--accept-list: unknown list id '{v}'")),
        }
    }
    let lists_dir = cfg.state_dir.join("lists");
    std::fs::create_dir_all(&lists_dir).map_err(|e| e.to_string())?;
    let mut rules = vec![];
    let mut unsupported: Vec<(String, String)> = vec![];
    for l in cfg.enabled() {
        let got = if offline {
            let have = lists_dir.join(format!("{}.txt", l.id)).exists() || lists_dir.join(format!("{}.new", l.id)).exists();
            if have { fetch::Got::NotModified } else { return Err(format!("no good copy of list {} (offline)", l.id)); }
        } else { fetch::fetch(l, &lists_dir, cfg.fetch_timeout_s, cfg.max_list_bytes)? };
        // Read whatever this run staged (or a previous run staged and never promoted/discarded),
        // never the promoted copy directly — a garbage 200 must reach the valve before it can
        // ever become "the" list. A staged body AGH would reject (HTML,
        // binary, not UTF-8) never gets that far: `load` falls back to the last good copy and
        // reports the list stale.
        // Per-list valve: a staged body is compared with the promoted copy (the list as
        // of the last commit); a drop beyond max_drop falls back to that copy (stale: valve …).
        let base = if fetch::staged(l, &lists_dir) && !accepted.contains(&l.id) {
            fetch::promoted_text(l, &lists_dir)?.map(|t| rule_count(&t, l.id))
        } else { None };
        let (text, got) = fetch::load(l, &lists_dir, got, |t| match base {
            Some(b) => {
                let n = rule_count(t, l.id);
                if (n as f64) < (b as f64) * (1.0 - cfg.max_drop) {
                    Err(format!("valve {n} < {b} x (1 - {})", cfg.max_drop))
                } else { Ok(()) }
            }
            None => Ok(()),
        })?;
        if let fetch::Got::Stale(w) = &got {
            if w.starts_with("valve ") { eprintln!("dnsdoh.art-compile: list {} stale: {w}", l.id); }
        }
        let (mut n, mut unsup) = (0usize, 0usize);
        for line in text.lines() {
            match rule::parse_line(line, rule::Source::List(l.id)) {
                rule::Parsed::Rule(r) => { rules.push(r); n += 1; }
                rule::Parsed::Unsupported(c) => { unsupported.push((c, line.trim().to_string())); unsup += 1; }
                rule::Parsed::Skip => {}
            }
        }
        let src = match &got { fetch::Got::Fresh => json!("fresh"), fetch::Got::NotModified => json!("cached"), fetch::Got::Stale(w) => json!(format!("stale: {w}")) };
        status["lists"].as_array_mut().unwrap().push(json!({"id": l.id, "name": l.name, "enabled": true, "source": src, "rules": n, "unsupported": unsup}));
    }
    for l in cfg.list.iter().filter(|l| !l.enabled) {
        status["lists"].as_array_mut().unwrap().push(json!({"id": l.id, "name": l.name, "enabled": false, "source": "disabled", "rules": 0, "unsupported": 0}));
    }
    let user = std::fs::read_to_string(&cfg.user_rules).map_err(|e| format!("{}: {e}", cfg.user_rules.display()))?;
    let mut user_n = 0;
    for (i, line) in user.lines().enumerate() {
        match rule::parse_line(line, rule::Source::User(i + 1)) {
            rule::Parsed::Rule(r) => { rules.push(r); user_n += 1; }
            rule::Parsed::Skip => {}
            // The rule text is redacted here; run() redacts the whole message again.
            rule::Parsed::Unsupported(c) => return Err(format!("user-rules.txt:{}: {c}: {}", i + 1, report::redact_clients(line))),
        }
    }
    let rw_text = std::fs::read_to_string(&cfg.rewrites).map_err(|e| format!("{}: {e}", cfg.rewrites.display()))?;
    let rws = rewrites::parse_rewrites(&rw_text)?;
    let (t, notes) = resolve::resolve(rules, &rws);
    unsupported.extend(notes.unsupported.iter().cloned());
    status["user_rules"] = json!(user_n);
    status["rewrites"] = json!(rws.iter().map(|(n, a)| json!({"name": n, "answer": a})).collect::<Vec<_>>());
    status["unsupported"] = report::classes(&unsupported);
    status["badfiltered"] = json!(notes.badfiltered);
    status["pruned_allows"] = json!(notes.pruned_allows);
    status["conflicts"] = json!(notes.conflicts);
    status["tables"] = json!({"allow_exact": t.allow_exact.len(), "allow": t.allow.len(), "block": t.block.len(), "block_nx": t.block_nx.len(),
        "pattern_keys": t.pattern.len(), "pattern_open_keys": t.pattern_open.len(), "scan": t.scan.len(), "ip_block": t.ip_block.len(), "rewrite": t.rewrite.len(), "client": t.client.len()});
    // Counts only: operator-configured client addresses never go into the status file.
    status["client_rules"] = json!(notes.client_rules);
    if !notes.conflicts.is_empty() { return Err(format!("conflict: {} precedence conflicts the tables cannot express", notes.conflicts.len())); }
    // Absolute floor, first run included (the Phase 2 seeder refused < 1000 block domains).
    if (t.block.len() as u64) < cfg.min_block {
        return Err(format!("safety valve: block count {} below minimum {}", t.block.len(), cfg.min_block));
    }
    let last_path = cfg.state_dir.join("last-commit.json");
    let last_text = match std::fs::read_to_string(&last_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("safety valve: last-commit.json unreadable: {}: {e}", last_path.display())),
    };
    if let Some(s) = last_text {
        // A present-but-unparsable (or unreadable) last-commit.json must refuse, not silently
        // disable the valve. A MISSING file (first
        // run) is the only case that skips the relative check; the floor above still applies.
        let v = serde_json::from_str::<serde_json::Value>(&s).ok();
        let last = match v.as_ref().and_then(|v| v["block"].as_u64()) {
            Some(n) => n,
            None => return Err(format!("safety valve: last-commit.json unreadable: {}: not a JSON object with a numeric \"block\" field", last_path.display())),
        };
        // A deliberate enable/disable changes the set of lists; the drop that
        // follows is intended, so the TOTAL valve is skipped for this run. The min_block floor and
        // every per-list valve still apply. A last-commit.json from before this change has no
        // "lists" and counts as the same set (the valve applies).
        let mut prev: Option<Vec<u64>> = v.as_ref().and_then(|v| v.get("lists")).and_then(|l| serde_json::from_value(l.clone()).ok());
        if let Some(p) = prev.as_mut() { p.sort_unstable(); p.dedup(); }   // compare as a set: cur is sorted and unique
        let cur = cfg.enabled_ids();
        match prev {
            Some(p) if p != cur => { status["valve_skipped"] = json!(format!("enabled lists changed: {p:?} -> {cur:?}")); }
            _ => if (t.block.len() as f64) < (last as f64) * (1.0 - cfg.max_drop) {
                return Err(format!("safety valve: block count {} < {} x (1 - {})", t.block.len(), last, cfg.max_drop));
            }
        }
    }
    let (rows, skipped) = emit::rows(&t);
    status["names_skipped_invalid"] = json!(skipped);
    if dry { return Ok(()); }
    let db = lmdb::Db::open(&cfg.db, cfg.map_size_mib << 20, false).map_err(|e| format!("lmdb: {e}"))?;
    let refs: Vec<(&str, emit::Rows)> = rows.into_iter().collect();
    db.replace_all(&refs).map_err(|e| format!("lmdb: {e}"))?;
    let (used, map) = db.usage();
    status["map"] = json!({"used_bytes": used, "size_bytes": map});
    status["committed"] = json!(true);
    // Post-commit bookkeeping (last-commit.json, promoting staged list files) happens in run(),
    // outside this function's `?`-chain, so it can never turn a committed DB into a refusal.
    status["block_count"] = json!(t.block.len());
    Ok(())
}

fn patterns() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        if let rule::Parsed::Rule(r) = rule::parse_line(&line, rule::Source::List(1)) {
            if let rule::Shape::Pattern(Some(p)) = &r.shape {
                println!("{}\t{:?}\t{}", r.text, p.key(), p.lua_patterns().join("\x1f"));
            }
        }
    }
}

fn kv_cmd(args: &[String]) -> Result<i32, String> {
    let get = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    let db = lmdb::Db::open(Path::new(&get("--db").ok_or("--db")?), 1024 << 20, args[0] == "get")?;
    let table = get("--table").ok_or("--table")?;
    let key = match (get("--name"), get("--text"), get("--hex")) {
        (Some(n), _, _) => emit::wire(&n).ok_or("bad name")?,
        (_, Some(t), _) => t.into_bytes(),
        (_, _, Some(h)) => (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16)).collect::<Result<_, _>>().map_err(|e| e.to_string())?,
        _ => return Err("--name, --text or --hex".into()),
    };
    if args[0] == "put" {
        // `#pf`/`#gen` summarise the pattern tables; a put there keeps them true.
        let derive = |rows: &dyn Fn(&str) -> Result<emit::Rows, String>| emit::derive_thread_rows(&table, rows);
        db.put_one(&table, &key, get("--value").ok_or("--value")?.as_bytes(), &derive)?;
    }
    else { println!("{}", String::from_utf8_lossy(&db.get(&table, &key)?.unwrap_or_default())); }
    Ok(0)
}
