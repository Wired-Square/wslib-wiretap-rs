#![cfg(feature = "ts")]
//! A histogram bin's declaration against its JSON, under the desktop's `Config`
//! (`large_int` as `number`).

use serde_json::json;
use ts_rs::{Config, TS};
use wiretap_analysis::dashboard::HistogramBin;

#[test]
fn a_histogram_bin_is_four_numbers() {
    let bin = HistogramBin {
        min: 0.0,
        max: 1.5,
        centre: 0.75,
        count: 3,
    };
    assert_eq!(
        serde_json::to_value(bin).unwrap(),
        json!({ "min": 0.0, "max": 1.5, "centre": 0.75, "count": 3 })
    );
    assert_eq!(
        HistogramBin::decl(&Config::new().with_large_int("number")),
        "type HistogramBin = { min: number, max: number, centre: number, count: number, };"
    );
}
