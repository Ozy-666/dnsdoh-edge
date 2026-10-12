//! `/etc/dnsdoh.art/compile.toml`.
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub db: PathBuf,
    pub state_dir: PathBuf,
    pub user_rules: PathBuf,
    pub rewrites: PathBuf,
    /// Lists in a separate file, owned by dnsdoh.art-edit. Exclusive with
    /// inline `[[list]]`, which compile.example.toml keeps using.
    #[serde(default)] pub lists: Option<PathBuf>,
    #[serde(default = "d_map")] pub map_size_mib: usize,
    #[serde(default = "d_drop")] pub max_drop: f64,
    /// Safety valve floor: refuse any result with fewer block names.
    #[serde(default = "d_min_block")] pub min_block: u64,
    #[serde(default = "d_timeout")] pub fetch_timeout_s: u64,
    #[serde(default = "d_max")] pub max_list_bytes: u64,
    #[serde(default)] pub list: Vec<ListCfg>,
}
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ListCfg {
    pub id: u64, pub name: String, pub url: String,
    #[serde(default = "d_true")] pub enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListsFile { #[serde(default)] list: Vec<ListCfg> }

fn d_true() -> bool { true }
fn d_map() -> usize { 1024 }
fn d_drop() -> f64 { 0.25 }
fn d_min_block() -> u64 { 1000 }
fn d_timeout() -> u64 { 60 }
fn d_max() -> u64 { 64 << 20 }

pub fn load(path: &std::path::Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut c: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    match (&c.lists, c.list.is_empty()) {
        (Some(_), false) => return Err(format!("{}: both `lists =` and [[list]]: use one", path.display())),
        (None, true) => return Err(format!("{}: no lists: set `lists =` or add [[list]]", path.display())),
        (Some(p), true) => {
            let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let f: ListsFile = toml::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))?;
            c.list = f.list;
        }
        (None, false) => {}
    }
    let mut seen = std::collections::HashSet::new();
    for l in &c.list {
        if !seen.insert(l.id) { return Err(format!("{}: duplicate list id {}", path.display(), l.id)); }
    }
    Ok(c)
}

impl Config {
    pub fn enabled(&self) -> impl Iterator<Item = &ListCfg> { self.list.iter().filter(|l| l.enabled) }
    pub fn enabled_ids(&self) -> Vec<u64> { let mut v: Vec<u64> = self.enabled().map(|l| l.id).collect(); v.sort_unstable(); v }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp(name: &str, body: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cfgtest-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name); std::fs::write(&p, body).unwrap(); p
    }
    const HEAD: &str = "db = \"/x.mdb\"\nstate_dir = \"/s\"\nuser_rules = \"/u\"\nrewrites = \"/r\"\n";
    const L2: &str = "[[list]]\nid = 1\nname = \"a\"\nurl = \"https://a/\"\n[[list]]\nid = 7\nname = \"b\"\nurl = \"https://b/\"\nenabled = false\n";

    #[test] fn inline_lists_default_enabled() {
        let c = load(&tmp("inline.toml", &format!("{HEAD}[[list]]\nid = 1\nname = \"a\"\nurl = \"https://a/\"\n"))).unwrap();
        assert!(c.list[0].enabled);
    }
    #[test] fn lists_file_merged_and_enabled_ids() {
        let lf = tmp("lists.toml", L2);
        let c = load(&tmp("c.toml", &format!("{HEAD}lists = \"{}\"\n", lf.display()))).unwrap();
        assert_eq!(c.list.len(), 2);
        assert_eq!(c.enabled_ids(), vec![1]);
        assert_eq!(c.enabled().count(), 1);
    }
    #[test] fn both_forms_refused() {
        let lf = tmp("lists2.toml", L2);
        let e = load(&tmp("both.toml", &format!("{HEAD}lists = \"{}\"\n{L2}", lf.display()))).unwrap_err();
        assert!(e.contains("use one"), "{e}");
    }
    #[test] fn neither_form_refused() {
        let e = load(&tmp("none.toml", HEAD)).unwrap_err();
        assert!(e.contains("no lists"), "{e}");
    }
    #[test] fn duplicate_id_refused() {
        let e = load(&tmp("dup.toml", &format!("{HEAD}{}", L2.replace("id = 7", "id = 1")))).unwrap_err();
        assert!(e.contains("duplicate list id 1"), "{e}");
    }
    #[test] fn unknown_field_in_lists_file_refused() {
        let lf = tmp("lists3.toml", "[[list]]\nid = 1\nname = \"a\"\nurl = \"https://a/\"\nenable = true\n");
        assert!(load(&tmp("c3.toml", &format!("{HEAD}lists = \"{}\"\n", lf.display()))).is_err());
    }
}
