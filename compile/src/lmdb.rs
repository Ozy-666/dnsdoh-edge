//! Minimal FFI to the system liblmdb 0.9.x — the library dnsdist links. One write
//! transaction per commit; the map size is fixed because dnsdist opens read-only with map
//! size 0 and adopts the file's (dnsdist-kvs.hh:187).
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::path::Path;

#[repr(C)] pub struct MdbEnv { _p: [u8; 0] }
#[repr(C)] pub struct MdbTxn { _p: [u8; 0] }
#[repr(C)] pub struct MdbCursor { _p: [u8; 0] }
#[repr(C)] struct MdbVal { mv_size: usize, mv_data: *mut c_void }
#[repr(C)] struct MdbStat { ms_psize: c_uint, ms_depth: c_uint, ms_branch_pages: usize, ms_leaf_pages: usize, ms_overflow_pages: usize, ms_entries: usize }
#[repr(C)] struct MdbEnvInfo { me_mapaddr: *mut c_void, me_mapsize: usize, me_last_pgno: usize, me_last_txnid: usize, me_maxreaders: c_uint, me_numreaders: c_uint }

const MDB_NOSUBDIR: c_uint = 0x4000;
const MDB_RDONLY: c_uint = 0x20000;
const MDB_CREATE: c_uint = 0x40000;
const MDB_NOTFOUND: c_int = -30798;
const MDB_FIRST: c_uint = 0;
const MDB_NEXT: c_uint = 8;

#[link(name = "lmdb")]
extern "C" {
    fn mdb_version(major: *mut c_int, minor: *mut c_int, patch: *mut c_int) -> *const c_char;
    fn mdb_strerror(err: c_int) -> *const c_char;
    fn mdb_env_create(env: *mut *mut MdbEnv) -> c_int;
    fn mdb_env_set_mapsize(env: *mut MdbEnv, size: usize) -> c_int;
    fn mdb_env_set_maxdbs(env: *mut MdbEnv, dbs: c_uint) -> c_int;
    fn mdb_env_open(env: *mut MdbEnv, path: *const c_char, flags: c_uint, mode: u32) -> c_int;
    fn mdb_env_close(env: *mut MdbEnv);
    fn mdb_env_info(env: *mut MdbEnv, info: *mut MdbEnvInfo) -> c_int;
    fn mdb_env_stat(env: *mut MdbEnv, stat: *mut MdbStat) -> c_int;
    fn mdb_txn_begin(env: *mut MdbEnv, parent: *mut MdbTxn, flags: c_uint, txn: *mut *mut MdbTxn) -> c_int;
    fn mdb_txn_commit(txn: *mut MdbTxn) -> c_int;
    fn mdb_txn_abort(txn: *mut MdbTxn);
    fn mdb_dbi_open(txn: *mut MdbTxn, name: *const c_char, flags: c_uint, dbi: *mut c_uint) -> c_int;
    fn mdb_drop(txn: *mut MdbTxn, dbi: c_uint, del: c_int) -> c_int;
    fn mdb_put(txn: *mut MdbTxn, dbi: c_uint, key: *mut MdbVal, data: *mut MdbVal, flags: c_uint) -> c_int;
    fn mdb_get(txn: *mut MdbTxn, dbi: c_uint, key: *mut MdbVal, data: *mut MdbVal) -> c_int;
    fn mdb_cursor_open(txn: *mut MdbTxn, dbi: c_uint, cursor: *mut *mut MdbCursor) -> c_int;
    fn mdb_cursor_get(cursor: *mut MdbCursor, key: *mut MdbVal, data: *mut MdbVal, op: c_uint) -> c_int;
    fn mdb_cursor_close(cursor: *mut MdbCursor);
}

fn check(rc: c_int, what: &str) -> Result<(), String> {
    if rc == 0 { return Ok(()); }
    let msg = unsafe { CStr::from_ptr(mdb_strerror(rc)) }.to_string_lossy();
    Err(format!("{what}: {msg}"))
}

fn val(b: &[u8]) -> MdbVal { MdbVal { mv_size: b.len(), mv_data: b.as_ptr() as *mut c_void } }

/// Every row of a table in key order (empty when the table does not exist).
fn rows_in(txn: *mut MdbTxn, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let cname = CString::new(table).unwrap();
    let mut dbi = 0;
    match unsafe { mdb_dbi_open(txn, cname.as_ptr(), 0, &mut dbi) } {
        0 => {}
        MDB_NOTFOUND => return Ok(vec![]),
        rc => check(rc, "open")?,
    }
    let mut cur = std::ptr::null_mut();
    check(unsafe { mdb_cursor_open(txn, dbi, &mut cur) }, "mdb_cursor_open")?;
    let mut out = vec![];
    let mut op = MDB_FIRST;
    let r = loop {
        let mut k = MdbVal { mv_size: 0, mv_data: std::ptr::null_mut() };
        let mut v = MdbVal { mv_size: 0, mv_data: std::ptr::null_mut() };
        match unsafe { mdb_cursor_get(cur, &mut k, &mut v, op) } {
            0 => out.push(unsafe { (std::slice::from_raw_parts(k.mv_data as *const u8, k.mv_size).to_vec(),
                                    std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size).to_vec()) }),
            MDB_NOTFOUND => break Ok(out),
            rc => break check(rc, "mdb_cursor_get").map(|_| vec![]),
        }
        op = MDB_NEXT;
    };
    unsafe { mdb_cursor_close(cur) };
    r
}

/// Rows derived from the tables as they are inside a write txn: (table, key, value) to put.
pub type Derive<'a> = &'a dyn Fn(&dyn Fn(&str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>) -> Result<Vec<(&'static str, Vec<u8>, Vec<u8>)>, String>;

#[derive(Debug)]
pub struct Db { env: *mut MdbEnv }
impl Drop for Db { fn drop(&mut self) { unsafe { mdb_env_close(self.env) } } }

impl Db {
    pub fn open(path: &Path, map_size: usize, readonly: bool) -> Result<Db, String> {
        let (mut ma, mut mi, mut pa) = (0, 0, 0);
        unsafe { mdb_version(&mut ma, &mut mi, &mut pa) };
        if (ma, mi) != (0, 9) { return Err(format!("liblmdb {ma}.{mi}.{pa}: dnsdist reads the 0.9 format only")); }
        // A zero-length file (e.g. `: > f.mdb`, or a crashed prior run) must count as "new": if
        // treated as existing, mdb_env_set_mapsize below is skipped, LMDB initialises the empty
        // file with its own default 1 MiB map before the size check further down can refuse, and
        // the file is stuck at 1 MiB forever — we never resize under readers, so there is no way
        // to fix it after the fact short of deleting the file, which we must not do while dnsdist
        // runs.
        let existed = std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);
        let mut env = std::ptr::null_mut();
        check(unsafe { mdb_env_create(&mut env) }, "mdb_env_create")?;
        let db = Db { env };
        check(unsafe { mdb_env_set_maxdbs(env, 16) }, "mdb_env_set_maxdbs")?;
        if !existed && !readonly { check(unsafe { mdb_env_set_mapsize(env, map_size) }, "mdb_env_set_mapsize")?; }
        let p = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
        let flags = MDB_NOSUBDIR | if readonly { MDB_RDONLY } else { 0 };
        check(unsafe { mdb_env_open(env, p.as_ptr(), flags, 0o640) }, "mdb_env_open")?;
        if !readonly && db.usage().1 != map_size {
            return Err(format!("map size of {} is {} bytes, config says {map_size}: refusing (never resize under readers)", path.display(), db.usage().1));
        }
        Ok(db)
    }

    /// (bytes in use, map size).
    pub fn usage(&self) -> (usize, usize) {
        let mut i: MdbEnvInfo = unsafe { std::mem::zeroed() };
        let mut s: MdbStat = unsafe { std::mem::zeroed() };
        unsafe { mdb_env_info(self.env, &mut i); mdb_env_stat(self.env, &mut s) };
        ((i.me_last_pgno + 1) * s.ms_psize as usize, i.me_mapsize)
    }

    /// Replaces every listed table in ONE write transaction; any error aborts it and
    /// readers keep the previous data.
    pub fn replace_all(&self, tables: &[(&str, Vec<(Vec<u8>, Vec<u8>)>)]) -> Result<(), String> {
        let mut txn = std::ptr::null_mut();
        check(unsafe { mdb_txn_begin(self.env, std::ptr::null_mut(), 0, &mut txn) }, "mdb_txn_begin")?;
        let res = (|| -> Result<(), String> {
            for (name, rows) in tables {
                let cname = CString::new(*name).unwrap();
                let mut dbi = 0;
                check(unsafe { mdb_dbi_open(txn, cname.as_ptr(), MDB_CREATE, &mut dbi) }, &format!("open table {name}"))?;
                check(unsafe { mdb_drop(txn, dbi, 0) }, &format!("empty table {name}"))?;
                for (k, v) in rows {
                    let (mut kv, mut vv) = (val(k), val(v));
                    check(unsafe { mdb_put(txn, dbi, &mut kv, &mut vv, 0) }, &format!("put into {name}"))?;
                }
            }
            Ok(())
        })();
        match res {
            Ok(()) => check(unsafe { mdb_txn_commit(txn) }, "mdb_txn_commit"),
            Err(e) => { unsafe { mdb_txn_abort(txn) }; Err(e) }
        }
    }

    /// Tests only: one key into one table, then the rows `derive` returns (it reads tables as
    /// they are after that put), all in one txn.
    pub fn put_one(&self, table: &str, key: &[u8], value: &[u8], derive: Derive) -> Result<(), String> {
        let mut txn = std::ptr::null_mut();
        check(unsafe { mdb_txn_begin(self.env, std::ptr::null_mut(), 0, &mut txn) }, "mdb_txn_begin")?;
        let put = |table: &str, key: &[u8], value: &[u8]| -> Result<(), String> {
            let cname = CString::new(table).unwrap();
            let mut dbi = 0;
            check(unsafe { mdb_dbi_open(txn, cname.as_ptr(), MDB_CREATE, &mut dbi) }, "open")?;
            let (mut k, mut v) = (val(key), val(value));
            check(unsafe { mdb_put(txn, dbi, &mut k, &mut v, 0) }, "put")
        };
        let r = put(table, key, value).and_then(|_| {
            for (t, k, v) in derive(&|name: &str| rows_in(txn, name))? { put(t, &k, &v)?; }
            Ok(())
        });
        match r { Ok(()) => check(unsafe { mdb_txn_commit(txn) }, "commit"), Err(e) => { unsafe { mdb_txn_abort(txn) }; Err(e) } }
    }

    pub fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut txn = std::ptr::null_mut();
        check(unsafe { mdb_txn_begin(self.env, std::ptr::null_mut(), MDB_RDONLY, &mut txn) }, "mdb_txn_begin")?;
        let cname = CString::new(table).unwrap();
        let mut dbi = 0;
        let out = check(unsafe { mdb_dbi_open(txn, cname.as_ptr(), 0, &mut dbi) }, "open").and_then(|_| {
            let mut k = val(key);
            let mut v = MdbVal { mv_size: 0, mv_data: std::ptr::null_mut() };
            match unsafe { mdb_get(txn, dbi, &mut k, &mut v) } {
                0 => Ok(Some(unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }.to_vec())),
                MDB_NOTFOUND => Ok(None),
                rc => check(rc, "get").map(|_| None),
            }
        });
        unsafe { mdb_txn_abort(txn) };
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lmdbtest-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&d).unwrap(); d.join("t.mdb")
    }
    #[test] fn replace_is_atomic_and_aborts_on_error() {
        let p = tmp(); let db = Db::open(&p, 64 << 20, false).unwrap();
        db.replace_all(&[("a", vec![(b"k".to_vec(), b"v1".to_vec())])]).unwrap();
        // A 600-byte key exceeds MDB_MAXKEYSIZE (511): the whole txn must abort.
        let bad = db.replace_all(&[("a", vec![(b"k".to_vec(), b"v2".to_vec())]), ("b", vec![(vec![b'x'; 600], b"v".to_vec())])]);
        assert!(bad.is_err());
        assert_eq!(db.get("a", b"k").unwrap(), Some(b"v1".to_vec()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
    #[test] fn map_full_keeps_old_data() {
        let p = tmp(); let db = Db::open(&p, 1 << 20, false).unwrap();
        db.replace_all(&[("a", vec![(b"k".to_vec(), b"old".to_vec())])]).unwrap();
        let big: Vec<(Vec<u8>, Vec<u8>)> = (0..20000u32).map(|i| (i.to_be_bytes().to_vec(), vec![0u8; 200])).collect();
        let e = db.replace_all(&[("a", big)]).unwrap_err();
        assert!(e.contains("MDB_MAP_FULL"), "{e}");
        assert_eq!(db.get("a", b"k").unwrap(), Some(b"old".to_vec()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
    #[test] fn put_one_derives_from_rows_in_same_txn() {
        let p = tmp(); let db = Db::open(&p, 64 << 20, false).unwrap();
        db.replace_all(&[("a", vec![(b"k1".to_vec(), b"v1".to_vec())])]).unwrap();
        // derive sees the put (k2) and the old row (k1), in key order; its rows land in the same commit.
        let derive = |rows: &dyn Fn(&str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>| {
            let r = rows("a")?;
            assert!(rows("nosuch")?.is_empty());
            Ok(vec![("b", b"sum".to_vec(), r.iter().map(|(k, v)| [k.clone(), v.clone()].concat()).collect::<Vec<_>>().concat())])
        };
        db.put_one("a", b"k2", b"v2", &derive).unwrap();
        assert_eq!(db.get("b", b"sum").unwrap(), Some(b"k1v1k2v2".to_vec()));
        // a failing derive aborts the put too.
        let bad = |_: &dyn Fn(&str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>| -> Result<Vec<(&'static str, Vec<u8>, Vec<u8>)>, String> { Err("no".into()) };
        assert!(db.put_one("a", b"k3", b"v3", &bad).is_err());
        assert_eq!(db.get("a", b"k3").unwrap(), None);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
    #[test] fn refuses_other_map_size() {
        let p = tmp(); drop(Db::open(&p, 2 << 20, false).unwrap());
        assert!(Db::open(&p, 4 << 20, false).unwrap_err().contains("map size"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
    // Review fix round 1: a zero-length pre-created file (e.g. `: > f.mdb`) must be treated as
    // "new" — otherwise mdb_env_set_mapsize is skipped, LMDB initialises the empty file with its
    // default 1 MiB map before our size check can refuse, and the file is stuck at 1 MiB forever
    // (never resize under readers, so we can't fix it after the fact).
    #[test] fn empty_preexisting_file_is_treated_as_new() {
        let p = tmp(); std::fs::File::create(&p).unwrap();
        let db = Db::open(&p, 2 << 20, false).unwrap();
        assert_eq!(db.usage().1, 2 << 20);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
    // Pins the accepting side of the size check: reopening an existing (non-empty) file at the
    // SAME map size must succeed, not just the rejecting side.
    #[test] fn reopen_at_same_size_succeeds() {
        let p = tmp();
        drop(Db::open(&p, 3 << 20, false).unwrap());
        let db = Db::open(&p, 3 << 20, false).unwrap();
        assert_eq!(db.usage().1, 3 << 20);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
