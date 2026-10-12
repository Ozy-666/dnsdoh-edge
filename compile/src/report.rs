//! compile-status.json: always written, atomically. No client data.
use serde_json::{json, Value};
use std::path::Path;

pub fn write(dir: &Path, v: &Value) -> Result<(), String> {
    let tmp = dir.join("compile-status.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join("compile-status.json")).map_err(|e| e.to_string())
}

pub fn classes(unsupported: &[(String, String)]) -> Value {
    let mut m = serde_json::Map::new();
    for (c, r) in unsupported {
        let e = m.entry(c.clone()).or_insert_with(|| json!({"count": 0, "examples": []}));
        e["count"] = json!(e["count"].as_u64().unwrap() + 1);
        if e["examples"].as_array().unwrap().len() < 3 { e["examples"].as_array_mut().unwrap().push(json!(redact_clients(r))); }
    }
    Value::Object(m)
}

/// Operator client addresses never reach compile-status.json or stderr (which the
/// journal persists). Rule: from the FIRST `$` in the text, if anything after it mentions
/// `client` (ASCII, any case), everything after that `$` becomes `<redacted>`. No `$`, or no
/// `client` after the first one → unchanged. This does not depend on how the parser splits a
/// rule (a stray later `$`, a regex anchor, a typo), so it cannot fall behind it; the cost is
/// over-redaction (a regex's `$` anchor; a refusal whose class has a `$`, e.g. `modifier $x`,
/// when the rule also mentions client), which is acceptable in a report. Applied to rule texts (unsupported examples, the user-rules refusal) and to the
/// whole refusal message.
pub fn redact_clients(text: &str) -> String {
    match text.find('$') {
        Some(i) if text[i + 1..].to_ascii_lowercase().contains("client") => format!("{}<redacted>", &text[..=i]),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn redacts_client_values() {
        let cases = [
            ("||a.com^$client=10.20.30.41", "||a.com^$<redacted>"),                           // A
            ("||a.com^$client=10.0.0.1|~10.0.0.2,important", "||a.com^$<redacted>"),          // B
            (r#"@@||a.com^$client='Living Room TV'|"x""#, "@@||a.com^$<redacted>"),           // C
            (r"||a.com^$client=10.0.0.1\,10.0.0.2,important", "||a.com^$<redacted>"),         // D
            ("||a.com^$important,client=10.0.0.1,badfilter", "||a.com^$<redacted>"),          // E
            ("||x.example^$client=10.20.30.43,10.20.30.44", "||x.example^$<redacted>"),       // F
            ("||y.example^$client=10.20.30.45, 10.20.30.46", "||y.example^$<redacted>"),      // G
            ("||a*.com^$important,\tclient=10.20.30.55", "||a*.com^$<redacted>"),             // Jtab
            ("||a.com^$client =10.20.30.54", "||a.com^$<redacted>"),                          // Jsp
            ("||a.com^$~client=10.20.30.57", "||a.com^$<redacted>"),                          // Jtilde
            ("||a.com^$CLIENT=10.20.30.58", "||a.com^$<redacted>"),
            ("||a.com^$Client=10.20.30.59", "||a.com^$<redacted>"),
            // Fix round 4: a `$` after the client value no longer hides it (K1-K3).
            ("||a.com^$client=10.20.30.62$important", "||a.com^$<redacted>"),                 // K1
            ("||a.com^$client=10.20.30.63$x", "||a.com^$<redacted>"),                         // K2
            ("||a.com^$client='10.20.30.64$'", "||a.com^$<redacted>"),                        // K3
            // Regex: the first `$` is the anchor; over-redaction is acceptable.
            (r"/^ads\.x$/$client=10.20.30.60", r"/^ads\.x$<redacted>"),
            // BOM/CR are no longer trimmed; the address still goes.
            ("\u{feff}  ||a.com^$client=10.20.30.61 \r", "\u{feff}  ||a.com^$<redacted>"),
            // A whole refusal message: client classes carry no `$` (rule.rs), so the first `$` is
            // the rule's and the class survives — raw, or already redacted once (idempotent).
            ("user-rules.txt:2: modifier with an invalid name: ||a.com^$client =10.20.30.54",
             "user-rules.txt:2: modifier with an invalid name: ||a.com^$<redacted>"),
            ("user-rules.txt:3: client modifier with a client name: ||z.example^$client='LivingRoomTV'",
             "user-rules.txt:3: client modifier with a client name: ||z.example^$<redacted>"),
            ("user-rules.txt:3: client modifier on a non-plain rule: ||a*.com^$<redacted>",
             "user-rules.txt:3: client modifier on a non-plain rule: ||a*.com^$<redacted>"),
            // Unchanged: no `$`, or nothing after the first `$` mentions client.
            ("||a.com^", "||a.com^"),
            ("||client.example^", "||client.example^"),
            ("||client.example^$important", "||client.example^$important"),
            ("||client.example^$important$x", "||client.example^$important$x"),
            (r"/client$/", r"/client$/"),
            ("||é.example^$important", "||é.example^$important"),
            ("user-rules.txt:3: modifier $dnstype: ||^$dnstype=ANY", "user-rules.txt:3: modifier $dnstype: ||^$dnstype=ANY"),
        ];
        for (i, o) in cases { assert_eq!(redact_clients(i), o, "{i:?}"); }
    }
    #[test] fn classes_redact_examples() {
        let v = classes(&[("c".into(), "||a*.example^$client=10.20.30.41".into())]);
        assert_eq!(v["c"]["examples"][0], "||a*.example^$<redacted>");
    }
}
