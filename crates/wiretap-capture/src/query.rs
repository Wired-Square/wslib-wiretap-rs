use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rusqlite::types::Value;
use rusqlite::Connection;
use wiretap_gateway::{Sql, SqlValue};

use crate::error::Result;

/// Run a read-only `statement`, one `T` per row; setting `cancel` aborts it between
/// SQLite VM steps with [`CaptureError::Cancelled`](crate::CaptureError::Cancelled).
pub fn read_rows<T>(
    conn: &Connection,
    statement: &Sql,
    cancel: &Arc<AtomicBool>,
    map: impl FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let cancel = Arc::clone(cancel);
    conn.progress_handler(1000, Some(move || cancel.load(Ordering::Relaxed)))?;
    let rows = read_all(conn, statement, map);
    conn.progress_handler(0, None::<fn() -> bool>)?;
    rows
}

pub(crate) fn read_all<T>(
    conn: &Connection,
    statement: &Sql,
    mut map: impl FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let values = statement.values.iter().map(|v| match v {
        SqlValue::Integer(n) => Value::Integer(*n),
        SqlValue::Text(s) => Value::Text(s.clone()),
    });
    let mut stmt = conn.prepare_cached(&statement.sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(map(row)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CaptureError;

    const LONG: &str =
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 200000) SELECT COUNT(*) FROM n";

    fn long() -> Sql {
        Sql {
            sql: LONG.into(),
            values: Vec::new(),
        }
    }

    #[test]
    fn a_set_cancel_flag_stops_the_statement_and_is_then_forgotten() {
        let conn = crate::schema::migrated();

        let cancelled = read_rows(&conn, &long(), &Arc::new(AtomicBool::new(true)), |r| {
            r.get::<_, i64>(0)
        });

        assert!(
            matches!(cancelled, Err(CaptureError::Cancelled)),
            "{cancelled:?}"
        );
        let after: i64 = conn.query_row(LONG, [], |r| r.get(0)).unwrap();
        assert_eq!(after, 200_000);
    }

    #[test]
    fn values_bind_in_order() {
        let conn = crate::schema::migrated();
        let statement = Sql {
            sql: "SELECT ? || ?".into(),
            values: vec![SqlValue::Text("a'".into()), SqlValue::Integer(7)],
        };

        let rows = read_rows(&conn, &statement, &Arc::default(), |r| {
            r.get::<_, String>(0)
        })
        .unwrap();

        assert_eq!(rows, ["a'7"]);
    }
}
