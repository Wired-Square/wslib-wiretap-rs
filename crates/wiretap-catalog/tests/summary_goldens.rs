//! The catalogue summary against the desktop's report goldens in
//! `fixtures/desktop/`: `catalogReport.sbrxxx.{txt,md,screen.html,print.html}`
//! and `catalogReport.report-{edges,legacy}.{txt,md}`. Each golden is read back
//! into the facts it prints (counts, and per frame its id, name, length,
//! transmitter, interval, bus, signals and mux cases), the summary is mapped
//! onto the same facts, and every fact is compared. The layout and wording are
//! the desktop's; every fact where the lib differs is pinned below with the
//! TypeScript value, the lib's value and the reason (facts 12).

use std::path::PathBuf;

use serde_json::{json, Map, Value};
use wiretap_catalog::summary::{CaseRow, FrameRow, Interval, MuxRow, SignalRow};
use wiretap_catalog::{CatalogSummary, Endianness, Protocol};

fn read(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

/// (golden, fact, TypeScript value, the lib's value).
type Found = (String, String, Value, Value);

#[derive(Default)]
struct Differences(Vec<Found>);

impl Differences {
    fn compare(&mut self, golden: &str, fact: impl Into<String>, ts: &Value, lib: Value) {
        if *ts != lib {
            self.0.push((golden.into(), fact.into(), ts.clone(), lib));
        }
    }

    /// Objects by the TypeScript's keys, arrays element by element over the
    /// shorter, with a differing length as a fact of its own.
    fn diff(&mut self, golden: &str, fact: &str, ts: &Value, lib: &Value) {
        match (ts, lib) {
            (Value::Object(t), Value::Object(l)) => {
                for (k, v) in t {
                    let at = format!("{fact}.{k}");
                    self.diff(golden, &at, v, l.get(k).unwrap_or(&Value::Null));
                }
            }
            (Value::Array(t), Value::Array(l)) if t.iter().chain(l).any(Value::is_object) => {
                self.compare(
                    golden,
                    format!("{fact}.len"),
                    &json!(t.len()),
                    json!(l.len()),
                );
                for (i, (t, l)) in t.iter().zip(l).enumerate() {
                    self.diff(golden, &format!("{fact}[{i}]"), t, l);
                }
            }
            _ => self.compare(golden, fact, ts, lib.clone()),
        }
    }

    fn assert_pinned(self, pinned: &[Found]) {
        let unpinned: Vec<&Found> = self.0.iter().filter(|d| !pinned.contains(d)).collect();
        let stale: Vec<&Found> = pinned.iter().filter(|p| !self.0.contains(p)).collect();
        assert!(
            unpinned.is_empty() && stale.is_empty(),
            "unpinned differences: {unpinned:#?}\npinned but not found: {stale:#?}"
        );
    }
}

// ---------- the facts a golden prints ----------

#[derive(Default)]
struct Report {
    header: Map<String, Value>,
    frames: Vec<TsFrame>,
}

#[derive(Default)]
struct TsFrame {
    facts: Map<String, Value>,
    signals: Vec<Value>,
    mux: Option<TsMux>,
    /// Markdown's mux, which cannot say which mux a case after a nested one
    /// belongs to: its muxes, cases and signals in document order.
    mux_events: Vec<Value>,
}

struct TsMux {
    bits: String,
    name: Option<String>,
    cases: Vec<(String, Vec<Value>, Option<TsMux>)>,
}

impl TsFrame {
    fn new(heading: &str) -> Self {
        let (id, name) = match heading.split_once(" — ") {
            Some((id, name)) => (id, Some(unescape(name))),
            None => (heading, None),
        };
        let id = u64::from_str_radix(id.trim().trim_start_matches("0x"), 16).unwrap();
        let mut facts = Map::new();
        for (k, v) in [
            ("id", json!(id)),
            ("name", json!(name)),
            ("length", Value::Null),
            ("transmitter", Value::Null),
            ("interval", Value::Null),
            ("bus", Value::Null),
        ] {
            facts.insert(k.into(), v);
        }
        Self {
            facts,
            ..Default::default()
        }
    }

    /// `Length: 8`, `Transmitter: BMS`, `Interval: 100ms (default)`, `Bus: 1`.
    fn meta(&mut self, part: &str) {
        let (label, value) = part.split_once(": ").unwrap();
        let (key, value) = match label {
            "Length" | "len" => ("length", json!(value.parse::<u64>().unwrap())),
            "Transmitter" | "tx" => ("transmitter", json!(unescape(value))),
            "Bus" | "bus" => ("bus", json!(value.parse::<u64>().unwrap())),
            "Interval" => ("interval", interval(value)),
            other => panic!("{other}"),
        };
        self.facts.insert(key.into(), value);
    }

    /// The mux at nesting `depth` (1 is the frame's own).
    fn mux_at(&mut self, depth: usize) -> &mut Option<TsMux> {
        if depth == 1 {
            return &mut self.mux;
        }
        let parent = self.mux_at(depth - 1).as_mut().unwrap();
        &mut parent.cases.last_mut().unwrap().2
    }

    fn open_mux(&mut self, depth: usize, head: &str) {
        let head = mux_event(head);
        *self.mux_at(depth) = Some(TsMux {
            bits: head["mux"].as_str().unwrap().into(),
            name: head["name"].as_str().map(str::to_string),
            cases: Vec::new(),
        });
    }

    fn open_case(&mut self, depth: usize, label: &str) {
        let mux = self.mux_at(depth).as_mut().unwrap();
        mux.cases.push((label.into(), Vec::new(), None));
    }

    fn push_signal(&mut self, depth: usize, signal: Value) {
        if depth == 0 {
            self.signals.push(signal);
        } else {
            let mux = self.mux_at(depth).as_mut().unwrap();
            mux.cases.last_mut().unwrap().1.push(signal);
        }
    }

    fn value(&self) -> Value {
        let mut v = Value::Object(self.facts.clone());
        v["signals"] = json!(self.signals);
        if v.get("muxEvents").is_some() {
            v["muxEvents"] = json!(self.mux_events);
        } else {
            v["mux"] = self.mux.as_ref().map_or(Value::Null, TsMux::value);
        }
        v
    }
}

impl TsMux {
    fn value(&self) -> Value {
        json!({
            "bits": self.bits,
            "name": self.name,
            "caseLabels": self.cases.iter().map(|c| &c.0).collect::<Vec<_>>(),
            "cases": self.cases.iter().map(|(_, signals, mux)| json!({
                "signals": signals,
                "mux": mux.as_ref().map_or(Value::Null, TsMux::value),
            })).collect::<Vec<_>>(),
        })
    }
}

/// `0/8:` or `24/4 (Inner)`.
fn mux_event(head: &str) -> Value {
    let head = head.trim_end_matches(':');
    let (bits, name) = match head.split_once(" (") {
        Some((bits, name)) => (bits, Some(unescape(name.trim_end_matches(')')))),
        None => (head, None),
    };
    json!({ "mux": bits, "name": name })
}

fn interval(text: &str) -> Value {
    let default = text.ends_with(" (default)");
    let ms = text.trim_end_matches(" (default)").trim_end_matches("ms");
    json!([ms.parse::<u64>().unwrap(), default])
}

/// `-` is factor 1 and offset 0; else `x{factor} + {offset}`.
fn scale(text: &str) -> Value {
    if text == "-" {
        return json!([1.0, 0.0]);
    }
    let (f, o) = text.trim_start_matches('x').split_once(" + ").unwrap();
    json!([f.parse::<f64>().unwrap(), o.parse::<f64>().unwrap()])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&amp;", "&")
}

fn chars(s: &str, from: usize, to: usize) -> String {
    s.chars()
        .skip(from)
        .take(to.saturating_sub(from))
        .collect::<String>()
        .trim()
        .to_string()
}

fn count(s: &str) -> Value {
    json!(s.trim().replace(',', "").parse::<u64>().unwrap())
}

fn parse_text(text: &str) -> Report {
    let mut r = Report::default();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("  CAN CATALOG REPORT — ") {
            r.header.insert("name".into(), json!(name));
            for k in ["version", "role"] {
                r.header.insert(k.into(), Value::Null);
            }
        } else if let Some((label, value)) = line
            .strip_prefix("  ")
            .filter(|_| r.frames.is_empty())
            .and_then(|l| l.split_once(':'))
        {
            let value = value.trim();
            let h = &mut r.header;
            match label {
                "Version" => _ = h.insert("version".into(), count(value)),
                "Role" => _ = h.insert("role".into(), json!(value)),
                "Default Endianness" => _ = h.insert("defaultEndianness".into(), json!(value)),
                "Frames" => {
                    let (n, mux) = value.trim_end_matches(" mux)").split_once(" (").unwrap();
                    h.insert("frames".into(), count(n));
                    h.insert("muxFrames".into(), count(mux));
                }
                "Signals" => {
                    let (n, e) = value.trim_end_matches(" enums)").split_once(" (").unwrap();
                    h.insert("signals".into(), count(n));
                    h.insert("enums".into(), count(e));
                }
                "Confidence" => {
                    let n: Vec<Value> = value
                        .split(", ")
                        .map(|p| count(p.split(' ').next().unwrap()))
                        .collect();
                    h.insert("confidence".into(), json!(n));
                }
                _ => {}
            }
        } else if let Some(head) = line.strip_prefix("╔══ ") {
            r.frames
                .push(TsFrame::new(head.trim_end_matches('═').trim_end()));
        } else if let Some(body) = line.strip_prefix('║') {
            let frame = r.frames.last_mut().unwrap();
            let indent = body.len() - body.trim_start().len();
            let content = body.trim_start();
            let level = indent / 2;
            if let Some(head) = content.strip_prefix("MUX @ bit ") {
                frame.open_mux(level.div_ceil(2), head);
            } else if let Some(label) = content.strip_prefix("Case ") {
                frame.open_case((level - 1).div_ceil(2), label.trim_end_matches(':'));
            } else if content.starts_with(|c: char| c.is_ascii_digit()) {
                if level == 1 {
                    let rest = chars(content, 46, usize::MAX);
                    let (rest, confidence) = rest.rsplit_once(' ').unwrap();
                    let words: Vec<&str> = rest.split_whitespace().collect();
                    let scale_words = if words[0] == "-" { 1 } else { 3 };
                    frame.push_signal(
                        0,
                        json!({
                            "bits": chars(content, 0, 12),
                            "name30": chars(content, 14, 44),
                            "scale": scale(&words[..scale_words].join(" ")),
                            "unit": words[scale_words..].join(" "),
                            "confidence": confidence,
                        }),
                    );
                } else {
                    frame.push_signal(
                        (level - 2).div_ceil(2),
                        json!({
                            "bits": chars(content, 0, 10),
                            "name25": chars(content, 12, 37),
                            "confidence": chars(content, 39, usize::MAX),
                        }),
                    );
                }
            } else if level == 1 && content.contains(": ") && !content.starts_with("Bit Range") {
                frame.meta(content);
            }
        }
    }
    r
}

fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

fn parse_markdown(text: &str) -> Report {
    let mut r = Report::default();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("# CAN Catalog Report — ") {
            r.header.insert("name".into(), json!(name));
            for k in ["version", "role"] {
                r.header.insert(k.into(), Value::Null);
            }
        } else if let Some(head) = line.strip_prefix("### ").filter(|h| h.starts_with("0x")) {
            let mut frame = TsFrame::new(head);
            frame.facts.insert("muxEvents".into(), json!([]));
            r.frames.push(frame);
        } else if let Some(rest) = line.strip_prefix("- **") {
            let (label, n) = rest.split_once("**: ").unwrap();
            let conf = r
                .header
                .entry("confidence")
                .or_insert_with(|| json!([0, 0, 0, 0]));
            let i = ["High", "Medium", "Low", "None"]
                .iter()
                .position(|l| *l == label)
                .unwrap();
            conf[i] = count(n);
        } else if line.starts_with("| ") && r.frames.is_empty() {
            let c = cells(line);
            let key = match c[0].as_str() {
                "Version" => "version",
                "Role" => "role",
                "Default Endianness" => "defaultEndianness",
                "Frames" => "frames",
                "Mux Frames" => "muxFrames",
                "Enums" => "enums",
                "Signals" => "signals",
                _ => continue,
            };
            let v = c[1].parse::<u64>().map_or(json!(c[1]), |n| json!(n));
            r.header.insert(key.into(), v);
        } else if let Some(frame) = r.frames.last_mut() {
            let hashes = line.chars().take_while(|c| *c == '#').count();
            if let Some(head) = line[hashes..].strip_prefix(" Mux @ bit ") {
                frame.mux_events.push(mux_event(head));
            } else if let Some(label) = line.strip_prefix("**Case ") {
                frame
                    .mux_events
                    .push(json!({ "case": label.trim_end_matches(":**") }));
            } else if let Some(meta) = line
                .strip_prefix('*')
                .filter(|m| !m.starts_with('*') && m.contains(": "))
            {
                for part in meta.trim_end_matches('*').split(" | ") {
                    frame.meta(part);
                }
            } else if line.starts_with("| ") && !line.starts_with("| Bit Range") {
                let c = cells(line);
                let mut signal = json!({
                    "bits": c[0],
                    "name": c[1].trim_matches('`'),
                    "scale": scale(&c[2]),
                    "unit": c[3],
                });
                if c.len() == 5 {
                    signal["confidence"] = json!(c[4]);
                    frame.mux_events.push(signal);
                } else {
                    signal["signed"] = json!(c[4] == "yes");
                    signal["endian"] = json!(c[5]);
                    signal["confidence"] = json!(c[6]);
                    signal["notes"] = json!(c[7..].join("|"));
                    frame.push_signal(0, signal);
                }
            }
        }
    }
    r
}

fn text_between<'a>(line: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = line.find(open)? + open.len();
    let end = line[start..].find(close)? + start;
    Some(&line[start..end])
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    unescape(out.trim())
}

fn parse_html(text: &str) -> Report {
    let mut r = Report::default();
    let mut open_divs: Vec<bool> = Vec::new();
    let mut last_value = Value::Null;
    let mut row: Option<Vec<String>> = None;
    let confidence_labels = ["high", "medium", "low", "none"];
    r.header.insert("confidence".into(), json!([0, 0, 0, 0]));
    let mut last_badge = None;
    for line in text.lines().map(str::trim) {
        if let Some(name) = text_between(line, "<h1>Catalog Report — ", "</h1>") {
            r.header.insert("name".into(), json!(unescape(name)));
        } else if let Some(v) = text_between(line, "<div class=\"value\">", "</div>") {
            last_value = count(v);
        } else if let Some(label) = text_between(line, "<div class=\"label\">", "</div>") {
            let key = match label {
                "Frames" => "frames",
                "Mux Frames" => "muxFrames",
                "Enums" => "enums",
                _ => "signals",
            };
            r.header.insert(key.into(), last_value.clone());
        } else if let Some(e) = text_between(line, "endian: default (", ")</span>") {
            r.header
                .insert("defaultEndianness".into(), json!(e.to_lowercase()));
        } else if let Some(head) = text_between(line, "<h2>", "</h2>") {
            let mut frame = TsFrame::new(&strip_tags(head));
            frame.facts.insert("confidence".into(), json!([0, 0, 0, 0]));
            r.frames.push(frame);
            open_divs.clear();
        } else if r.frames.is_empty() {
            if let Some(b) = text_between(line, "<span class=\"badge conf-", "\">") {
                last_badge = confidence_labels.iter().position(|l| *l == b);
            } else if let Some(n) = text_between(line, "<span class=\"count\">", "</span>") {
                r.header["confidence"][last_badge.unwrap()] = count(n);
            }
        } else {
            if line.starts_with("<div") && !line.ends_with("</div>") {
                open_divs.push(line.starts_with("<div class=\"mux-block"));
            } else if line == "</div>" {
                open_divs.pop();
            }
            let depth = open_divs.iter().filter(|mux| **mux).count();
            let frame = r.frames.last_mut().unwrap();
            if line.starts_with("<span class=\"pill") {
                let pill = strip_tags(line);
                if pill.contains(": ") {
                    frame.meta(&pill);
                } else {
                    frame.facts.insert("interval".into(), interval(&pill));
                }
            } else if line.starts_with("<span class=\"badge conf-") {
                let (label, n) = strip_tags(line)
                    .split_once(' ')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap();
                let i = confidence_labels.iter().position(|l| *l == label).unwrap();
                frame.facts["confidence"][i] = count(&n);
            } else if let Some(head) =
                text_between(line, "<div class=\"mux-head\">Mux @ bit ", "</div>")
            {
                frame.open_mux(depth, head);
            } else if let Some(label) = text_between(line, ">Case ", "</div>") {
                frame.open_case(depth, label);
            } else if line == "<tr>" {
                row = Some(Vec::new());
            } else if line.starts_with("<td") {
                row.as_mut().unwrap().push(line.to_string());
            } else if line == "</tr>" {
                let tds = row.take().unwrap();
                if tds.is_empty() {
                    continue;
                }
                let has_enum = tds.len() == 9;
                let t = |i: usize| strip_tags(&tds[i]);
                frame.push_signal(
                    depth,
                    json!({
                        "bits": t(0),
                        "name": t(1),
                        "scale": scale(&t(2)),
                        "unit": t(3),
                        "signed": t(4) == "yes",
                        "endian": t(5),
                        "endianOwn": tds[5].contains("end-override"),
                        "enum": if has_enum { t(6) } else { String::new() },
                        "confidence": t(if has_enum { 7 } else { 6 }),
                        "notes": t(if has_enum { 8 } else { 7 }),
                    }),
                );
            }
        }
    }
    r
}

// ---------- the same facts from the summary ----------

fn endian(e: Endianness) -> &'static str {
    match e {
        Endianness::Little => "LE",
        Endianness::Big => "BE",
    }
}

fn inherits(frame: &FrameRow, field: &str) -> bool {
    frame.inherited_fields.iter().any(|f| f == field)
}

fn own(signals: &[SignalRow]) -> impl Iterator<Item = &SignalRow> {
    signals.iter().filter(|s| !s.signal.inherited)
}

fn signal_facts(row: &SignalRow) -> Value {
    let s = &row.signal;
    let name = s.name.clone().unwrap_or_default();
    json!({
        "bits": format!("{}/{}", s.start_bit.unwrap_or(0), s.bit_length.unwrap_or(0)),
        "name": name,
        "name30": name.chars().take(30).collect::<String>(),
        "name25": name.chars().take(25).collect::<String>(),
        "scale": [s.factor.unwrap_or(1.0), s.offset.unwrap_or(0.0)],
        "unit": s.unit.clone().unwrap_or_default(),
        "signed": s.signed.unwrap_or(false),
        "endian": endian(row.byte_order),
        "endianOwn": s.endianness.is_some(),
        "enum": s.enum_map.iter().flatten().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", "),
        "confidence": s.confidence.map_or("none", |c| c.as_str()),
        "notes": s.notes.join("; "),
    })
}

fn case_label(case: &CaseRow) -> String {
    case.values
        .iter()
        .map(|r| match r.first == r.last {
            true => format!("0x{:X}", r.first),
            false => format!("0x{:X}-0x{:X}", r.first, r.last),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn mux_events(mux: &MuxRow, out: &mut Vec<Value>) {
    out.push(json!({ "mux": format!("{}/{}", mux.start_bit, mux.bit_length), "name": mux.name }));
    for case in &mux.cases {
        out.push(json!({ "case": case_label(case) }));
        out.extend(own(&case.signals).map(signal_facts));
        if let Some(inner) = &case.mux {
            mux_events(inner, out);
        }
    }
}

fn mux_facts(mux: &MuxRow) -> Value {
    json!({
        "bits": format!("{}/{}", mux.start_bit, mux.bit_length),
        "name": mux.name,
        "caseLabels": mux.cases.iter().map(case_label).collect::<Vec<_>>(),
        "cases": mux.cases.iter().map(|c| json!({
            "signals": own(&c.signals).map(signal_facts).collect::<Vec<_>>(),
            "mux": c.mux.as_deref().map_or(Value::Null, mux_facts),
        })).collect::<Vec<_>>(),
    })
}

/// The frame's own signals at every depth, as the HTML's per-frame badges count them.
fn frame_confidence(frame: &FrameRow) -> Value {
    fn walk<'a>(signals: &'a [SignalRow], mux: Option<&'a MuxRow>, out: &mut Vec<&'a SignalRow>) {
        out.extend(own(signals));
        for case in mux.iter().flat_map(|m| &m.cases) {
            walk(&case.signals, case.mux.as_deref(), out);
        }
    }
    let mut all = Vec::new();
    walk(&frame.signals, own_mux(frame), &mut all);
    let n = |c: &str| {
        all.iter()
            .filter(|s| s.signal.confidence.map_or("none", |x| x.as_str()) == c)
            .count()
    };
    json!([n("high"), n("medium"), n("low"), n("none")])
}

fn own_mux(frame: &FrameRow) -> Option<&MuxRow> {
    frame.mux.as_ref().filter(|_| !inherits(frame, "mux"))
}

/// The interval when the frame or the protocol's default sets it, not the frame
/// it copies.
fn own_interval(frame: &FrameRow) -> Option<Interval> {
    frame
        .interval
        .filter(|i| i.default || !inherits(frame, "interval"))
}

/// What the frame resolves to that the reports, reading the authored TOML, do
/// not show: what it takes from the frame it mirrors or copies.
fn has_inherited_rows(frame: &FrameRow) -> bool {
    frame.signals.iter().any(|s| s.signal.inherited)
        || ["mux", "transmitter", "length"]
            .iter()
            .any(|f| inherits(frame, f))
        || frame.interval != own_interval(frame)
}

fn frame_facts(frame: &FrameRow) -> Value {
    let mut events = Vec::new();
    if let Some(mux) = own_mux(frame) {
        mux_events(mux, &mut events);
    }
    json!({
        "id": frame.frame_id,
        "name": frame.name,
        "length": (!inherits(frame, "length")).then_some(frame.length),
        "transmitter": frame.transmitter.as_ref().filter(|_| !inherits(frame, "transmitter")),
        "interval": own_interval(frame).map(|i| json!([i.ms, i.default])),
        "bus": frame.bus,
        "confidence": frame_confidence(frame),
        "signals": own(&frame.signals).map(signal_facts).collect::<Vec<_>>(),
        "mux": own_mux(frame).map_or(Value::Null, mux_facts),
        "muxEvents": events,
    })
}

fn header_facts(s: &CatalogSummary) -> Value {
    let c = &s.counts;
    let f = &c.frames;
    json!({
        "name": s.name,
        "version": s.version,
        "role": null,
        "defaultEndianness": serde_json::to_value(s.defaults.can_byte_order).unwrap(),
        "frames": f.can + f.modbus + f.serial,
        "muxFrames": c.mux_frames,
        "signals": c.signals,
        "enums": c.enum_signals,
        "confidence": [c.confidence.high, c.confidence.medium, c.confidence.low, c.confidence.none],
    })
}

fn compare_report(d: &mut Differences, golden: &str, ts: &Report, lib: &CatalogSummary) {
    d.diff(
        golden,
        "header",
        &Value::Object(ts.header.clone()),
        &header_facts(lib),
    );
    let can: Vec<&FrameRow> = lib
        .frames
        .iter()
        .filter(|f| f.protocol == Protocol::Can)
        .collect();
    let beyond: Vec<String> = lib
        .frames
        .iter()
        .filter(|f| f.protocol != Protocol::Can)
        .map(|f| {
            format!(
                "{}:{}",
                serde_json::to_value(f.protocol).unwrap().as_str().unwrap(),
                f.key
            )
        })
        .collect();
    d.compare(golden, "frames beyond CAN", &json!([]), json!(beyond));
    let inherited: Vec<&str> = can
        .iter()
        .filter(|f| has_inherited_rows(f))
        .map(|f| f.key.as_str())
        .collect();
    d.compare(
        golden,
        "frames with inherited rows",
        &json!([]),
        json!(inherited),
    );
    d.compare(
        golden,
        "frames.len",
        &json!(ts.frames.len()),
        json!(can.len()),
    );
    for (t, l) in ts.frames.iter().zip(&can) {
        let at = format!("frame {}", l.key);
        d.diff(golden, &at, &t.value(), &frame_facts(l));
    }
}

fn summary(toml: &str) -> CatalogSummary {
    CatalogSummary::from_text(&read(toml)).unwrap()
}

fn pin(goldens: &[&str], fact: &str, ts: Value, lib: Value) -> Vec<Found> {
    goldens
        .iter()
        .map(|g| (g.to_string(), fact.to_string(), ts.clone(), lib.clone()))
        .collect()
}

const SBRXXX: [&str; 4] = [
    "catalogReport.sbrxxx.txt",
    "catalogReport.sbrxxx.md",
    "catalogReport.sbrxxx.screen.html",
    "catalogReport.sbrxxx.print.html",
];
const EDGES: [&str; 2] = [
    "catalogReport.report-edges.txt",
    "catalogReport.report-edges.md",
];
const LEGACY: [&str; 2] = [
    "catalogReport.report-legacy.txt",
    "catalogReport.report-legacy.md",
];

fn parse_golden(name: &str) -> Report {
    let text = read(name);
    match name.rsplit('.').next().unwrap() {
        "txt" => parse_text(&text),
        "md" => parse_markdown(&text),
        _ => parse_html(&text),
    }
}

#[test]
fn the_summary_holds_every_fact_the_catalogue_reports_print() {
    let mut d = Differences::default();
    for (toml, goldens) in [
        ("sbrxxx.toml", &SBRXXX[..]),
        ("report-edges.toml", &EDGES[..]),
        ("report-legacy.toml", &LEGACY[..]),
    ] {
        let lib = summary(toml);
        for golden in goldens {
            compare_report(&mut d, golden, &parse_golden(golden), &lib);
        }
    }
    d.assert_pinned(&deviations());
}

/// Every fact the lib states differently, by golden: (fact, TypeScript, lib, why).
fn deviations() -> Vec<Found> {
    let mut out = Vec::new();
    let mut add = |goldens: &[&str], fact: &str, ts: Value, lib: Value, _why: &str| {
        out.extend(pin(goldens, fact, ts, lib));
    };
    let all_sbrxxx = &SBRXXX[..];
    let modbus_why = "facts 12: the report is CAN-only; the summary covers every protocol";
    add(
        all_sbrxxx,
        "frames beyond CAN",
        json!([]),
        json!(["modbus:tunnel_4de2_holding", "modbus:tunnel_4de2_input"]),
        modbus_why,
    );
    add(
        all_sbrxxx,
        "header.frames",
        json!(76),
        json!(78),
        modbus_why,
    );
    add(
        all_sbrxxx,
        "header.signals",
        json!(162),
        json!(170),
        modbus_why,
    );
    add(
        all_sbrxxx,
        "header.confidence",
        json!([117, 12, 17, 16]),
        json!([117, 12, 17, 24]),
        modbus_why,
    );
    add(
        &EDGES,
        "frames beyond CAN",
        json!([]),
        json!(["modbus:5000"]),
        modbus_why,
    );
    add(&EDGES, "header.frames", json!(3), json!(4), modbus_why);
    add(&EDGES, "header.signals", json!(5), json!(6), modbus_why);
    add(
        &EDGES,
        "header.confidence",
        json!([0, 1, 1, 3]),
        json!([0, 1, 1, 4]),
        modbus_why,
    );

    add(all_sbrxxx, "frames with inherited rows", json!([]), json!(SBRXXX_INHERITING),
        "a row is the resolved frame: what a mirror or copy inherits is in it, named by `inheritedFields` and each signal's `inherited`");

    let interval_ms = "facts 12: the report ignores `interval_ms`";
    for key in [
        "0x708", "0x709", "0x70A", "0x70B", "0x70D", "0x70E", "0x70F",
    ] {
        add(
            all_sbrxxx,
            &format!("frame {key}.interval"),
            Value::Null,
            json!([10000, false]),
            interval_ms,
        );
    }
    add(
        &EDGES,
        "frame 256.interval",
        json!([100, true]),
        json!([50, false]),
        interval_ms,
    );

    let byte_order = "facts 12: the report ignores a signal's `byte_order`";
    add(
        &SBRXXX[1..],
        "frame 0x401.signals[0].endian",
        json!("LE"),
        json!("BE"),
        byte_order,
    );
    add(
        &SBRXXX[2..],
        "frame 0x401.signals[0].endianOwn",
        json!(false),
        json!(true),
        byte_order,
    );

    add(&EDGES, "header.defaultEndianness", json!("big"), json!("little"),
        "facts 3, 12: `[meta] default_endianness` is not decode's; `[meta.can] default_byte_order` is");
    add(
        &EDGES,
        "header.role",
        json!("gateway"),
        Value::Null,
        "`[meta] role` is a pre-schema key nothing reads; the model has no role",
    );
    add(
        &EDGES,
        "frame 256.transmitter",
        json!("BMS, Charger"),
        Value::Null,
        "a transmitter is one node; the model reads no array (the legacy form), so there is none",
    );
    add(
        &EDGES,
        "frame 256.bus",
        Value::Null,
        json!(0),
        "facts 12: the report hides `bus = 0`",
    );
    let length = "an unset CAN length resolves to 8; the report prints only an authored one";
    add(&EDGES, "frame 0x7FF.length", Value::Null, json!(8), length);
    add(
        &EDGES,
        "frame 0x18FF0010.length",
        Value::Null,
        json!(8),
        length,
    );
    let parsed = "facts 12: a case's values are parsed, not parseInt of its key";
    let not_a_case = "facts 12, 18: the mux's `notes` array is not a case";
    add(
        &EDGES[..1],
        "frame 0x18FF0010.mux.caseLabels",
        json!(["0x0", "0xA", "0xNAN"]),
        json!(["0x0-0x3", "0xA,0xC"]),
        parsed,
    );
    add(
        &EDGES[..1],
        "frame 0x18FF0010.mux.cases.len",
        json!(3),
        json!(2),
        not_a_case,
    );
    add(
        &EDGES[1..],
        "frame 0x18FF0010.muxEvents[1].case",
        json!("0x0"),
        json!("0x0-0x3"),
        parsed,
    );
    add(
        &EDGES[1..],
        "frame 0x18FF0010.muxEvents[3].case",
        json!("0xA"),
        json!("0xA,0xC"),
        parsed,
    );
    add(
        &EDGES[1..],
        "frame 0x18FF0010.muxEvents.len",
        json!(9),
        json!(8),
        not_a_case,
    );

    add(
        &LEGACY,
        "header.name",
        json!("Untitled"),
        json!(""),
        "the title's fallback is the renderer's",
    );
    add(
        &LEGACY,
        "header.version",
        Value::Null,
        json!(1),
        "an unset version is 1 in the model",
    );
    out
}

/// sbrxxx's mirrors and copies.
const SBRXXX_INHERITING: [&str; 32] = [
    "0x000", "0x001", "0x002", "0x003", "0x004", "0x005", "0x006", "0x007", "0x008", "0x009",
    "0x00a", "0x00b", "0x00d", "0x00e", "0x013", "0x014", "0x015", "0x016", "0x017", "0x018",
    "0x019", "0x01A", "0x01b", "0x01c", "0x01d", "0x01e", "0x501", "0x502", "0x503", "0x504",
    "0x505", "0x506",
];
