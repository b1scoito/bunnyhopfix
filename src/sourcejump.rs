//! sourcejump — global CS:S bhop world-record lookup.
//!
//! On connect (from the ProcessServerInfo hook, which already has the map
//! name) we ask sourcejump.net for the map's records and print the WR + a few
//! top times to the tool's terminal log. Read-only, best-effort, and fully
//! off the engine thread so a slow API never stalls a connect.
//!
//! Output goes to stderr (where the tool's other `[rawinput2]` logs go and the
//! user is already watching). Printing into the in-game console would need an
//! engine command-buffer hook we don't have yet.

use std::sync::Mutex;

/// The community-shared read-only API key (same one rtldg/wrsj ships).
const PUBLIC_API_KEY: &str = "SJPublicAPIKey";
const API_BASE: &str = "https://sourcejump.net/api/records/";
/// How many rows to print (WR + a couple of chasers).
const SHOW_ROWS: usize = 3;
/// Only ever parse this much of the response (a map's record list is ~20-30KB;
/// this bounds in-process memory regardless of what the endpoint returns).
const MAX_BODY: usize = 512 * 1024;

/// Coordinates lookups: at most one worker thread, coalescing rapid map
/// changes to the most recent map so the one you actually land on wins, and
/// suppressing repeat lookups for a map already shown.
struct State {
    shown: String,           // last map we displayed
    inflight: bool,          // a worker thread is running
    pending: Option<String>, // most recent requested map not yet handled
}
static STATE: Mutex<State> = Mutex::new(State {
    shown: String::new(),
    inflight: false,
    pending: None,
});

/// Fire off a background WR lookup for `mapname`. Returns immediately.
pub fn show_wr(mapname: &str) {
    if mapname.is_empty()
        || mapname.len() > 64
        || !mapname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return; // never interpolate anything odd into a URL/subprocess
    }
    let Ok(mut st) = STATE.lock() else { return };
    if st.shown == mapname {
        return; // already displayed this map
    }
    st.pending = Some(mapname.to_string()); // newest request wins
    if st.inflight {
        return; // the running worker will pick it up
    }
    st.inflight = true;
    drop(st);
    if std::thread::Builder::new().spawn(worker).is_err() {
        if let Ok(mut st) = STATE.lock() {
            st.inflight = false;
        }
    }
}

/// Drains the pending map(s), newest-first, one fetch at a time.
fn worker() {
    loop {
        let map = {
            let Ok(mut st) = STATE.lock() else { return };
            match st.pending.take() {
                // mark shown up front so a repeat request while we fetch is
                // suppressed; a genuinely different newer map still coalesces
                // via `pending` and is handled on the next loop turn
                Some(m) if m != st.shown => {
                    st.shown = m.clone();
                    m
                }
                _ => {
                    st.inflight = false;
                    return;
                }
            }
        };
        fetch_and_print(&map);
    }
}

fn fetch_and_print(mapname: &str) {
    let url = format!("{API_BASE}{mapname}");
    let out = std::process::Command::new("curl")
        // --max-filesize bounds the download when the server sends a
        // Content-Length (SourceJump does); the parse cap below is the
        // in-process backstop.
        .args([
            "-fsS",
            "--max-time",
            "10",
            "--max-filesize",
            "4194304",
            "-H",
        ])
        .arg(format!("api-key: {PUBLIC_API_KEY}"))
        .arg(&url)
        .output();
    let Ok(out) = out else { return };
    if !out.status.success() {
        return;
    }
    // bound what we parse; from_utf8_lossy keeps char boundaries intact
    let raw = if out.stdout.len() > MAX_BODY {
        &out.stdout[..MAX_BODY]
    } else {
        &out.stdout[..]
    };
    let body = String::from_utf8_lossy(raw);
    let rows = parse_records(&body, SHOW_ROWS);
    if rows.is_empty() {
        log!("sourcejump: no records for {mapname}");
        return;
    }
    log!("sourcejump WRs for {mapname}:");
    // Also echo into the game console (if the ClientCmd interface armed). This
    // runs on a background thread, so queue_cmd marshals to the main thread.
    crate::engine::queue_cmd(format!("echo [SourceJump] {mapname}:"));
    for (i, r) in rows.iter().enumerate() {
        let tag = if i == 0 { "WR" } else { "  " };
        // e.g. "  WR 5:58.330  Jehoshaphat  (sync 93.8%, 614 strafes)"
        let line = format!(
            "  {tag} {:<10} {}  (sync {:.1}%, {} strafes)",
            r.time, r.name, r.sync, r.strafes
        );
        log!("{line}");
        // console `echo` splits on odd chars; keep it to a safe alnum subset
        let safe: String = line
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || " .:%()-_".contains(c) {
                    c
                } else {
                    ' '
                }
            })
            .collect();
        crate::engine::queue_cmd(format!("echo {}", safe.trim()));
    }
}

struct Record {
    time: String,
    name: String,
    sync: f64,
    strafes: i64,
}

/// Minimal, dependency-free extraction of the fields we show from the
/// SourceJump JSON array. The API returns records ordered fastest-first; we
/// just walk objects in order and pull four fields each. Not a general JSON
/// parser — tolerant of missing fields, stops after `limit` records.
fn parse_records(json: &str, limit: usize) -> Vec<Record> {
    let mut out = Vec::new();
    // split into top-level object chunks by '{' ... '}' is unsafe with nested
    // objects, but SourceJump records are flat; still, be defensive and scan
    // field-by-field within each object boundary.
    for obj in split_objects(json) {
        let time = str_field(&obj, "time");
        let name = str_field(&obj, "name");
        if time.is_none() && name.is_none() {
            continue;
        }
        out.push(Record {
            // both string fields come from other players / the API — strip
            // control chars (terminal-escape safety) and bound the length
            time: sanitize(&time.unwrap_or_else(|| "?".into())),
            name: sanitize(&name.unwrap_or_else(|| "?".into())),
            sync: num_field(&obj, "sync").unwrap_or(0.0),
            strafes: num_field(&obj, "strafes").map(|v| v as i64).unwrap_or(0),
        });
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Yield the substring of each top-level `{...}` object (flat objects only).
fn split_objects(json: &str) -> Vec<String> {
    let mut objs = Vec::new();
    let bytes = json.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b'{' {
            if depth == 0 {
                start = i;
            }
            depth += 1;
        } else if c == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 && i >= start {
                objs.push(json[start..=i].to_string());
                if objs.len() >= 64 {
                    break; // plenty; the caller only shows a few
                }
            }
        }
        i += 1;
    }
    objs
}

/// Extract a string field `"key":"value"` (value with no escaped quotes).
fn str_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after = &obj[obj.find(&needle)? + needle.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let rest = after.strip_prefix('"')?;
    // value ends at the next unescaped quote
    let mut end = 0;
    let b = rest.as_bytes();
    let mut esc = false;
    while end < b.len() {
        if esc {
            esc = false;
        } else if b[end] == b'\\' {
            esc = true;
        } else if b[end] == b'"' {
            break;
        }
        end += 1;
    }
    Some(rest[..end].to_string())
}

/// Extract a numeric field `"key":<number>` (possibly null).
fn num_field(obj: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{key}\"");
    let after = &obj[obj.find(&needle)? + needle.len()..];
    let after = after.trim_start().strip_prefix(':')?.trim_start();
    let end = after
        .find(|c: char| {
            !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E')
        })
        .unwrap_or(after.len());
    after[..end].parse().ok()
}

/// Keep names printable on one log line (they come from other players).
fn sanitize(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).take(24).collect();
    if cleaned.is_empty() {
        "?".into()
    } else {
        cleaned
    }
}
