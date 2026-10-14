use rusqlite::{params, Connection};
use wiretap_gateway::CaptureProtocol;
use wiretap_protocol::can::{CanFrame, Direction};
use wiretap_protocol::{dlc_to_len, len_to_dlc};

use crate::error::Result;

/// A frame's stored length: captures stored before WireTAP `2c4fb97e` hold a CAN FD
/// length code in `dlc`, always below the payload's length, and an RTR's `dlc`
/// is its requested length.
pub const STORED_LENGTH: &str = "MAX(dlc, length(payload))";

/// Every column [`row_to_frame`] reads; one it reads and a query omits fails at run time.
pub(crate) const FRAME_COLUMNS: &str = "rowid, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction";

/// One `frames` row: a CAN, CAN FD, Modbus or serial frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredFrame {
    /// Open, so a row written under a protocol this build doesn't know reads back as it was.
    pub protocol: String,
    pub timestamp_us: u64,
    pub frame_id: u32,
    pub bus: u8,
    /// A length, not a length code; an RTR's is the length it asks for.
    pub len: u16,
    pub payload: Vec<u8>,
    pub extended: bool,
    pub fd: bool,
    pub rtr: bool,
    pub brs: bool,
    pub esi: bool,
    pub source_address: Option<u16>,
    pub incomplete: Option<bool>,
    pub direction: Option<Direction>,
}

impl StoredFrame {
    /// A CAN frame as the capture stores it.
    pub fn can(timestamp_us: u64, frame: &CanFrame, direction: Direction) -> Self {
        let len = if frame.rtr {
            dlc_to_len(frame.dlc(), false)
        } else {
            frame.data.len()
        };
        Self {
            protocol: CaptureProtocol::Can.as_str().into(),
            timestamp_us,
            frame_id: frame.arb_id,
            bus: frame.bus,
            len: len as u16,
            payload: frame.data.clone(),
            extended: frame.extended,
            fd: frame.fd,
            rtr: frame.rtr,
            brs: frame.brs,
            esi: frame.esi,
            source_address: None,
            incomplete: None,
            direction: Some(direction),
        }
    }

    /// The CAN frame this row is, `None` for any other protocol.
    pub fn to_can(&self) -> Option<CanFrame> {
        let Some(CaptureProtocol::Can | CaptureProtocol::CanFd) = self.capture_protocol() else {
            return None;
        };
        let mut frame = if self.rtr {
            CanFrame::remote(
                self.bus,
                self.frame_id,
                self.extended,
                len_to_dlc(self.len.into()),
            )
        } else {
            CanFrame::data(
                self.bus,
                self.frame_id,
                self.extended,
                self.fd,
                self.brs,
                self.payload.clone(),
            )
        };
        frame.esi = self.esi;
        Some(frame)
    }

    /// The protocol, `None` when it isn't one a capture stores.
    pub fn capture_protocol(&self) -> Option<CaptureProtocol> {
        CaptureProtocol::from_stored(&self.protocol)
    }
}

/// A frame as an insert reads it, borrowed so the hot path copies nothing.
pub trait FrameRecord {
    fn protocol(&self) -> &str;
    fn timestamp_us(&self) -> u64;
    fn frame_id(&self) -> u32;
    fn bus(&self) -> u8;
    /// See [`StoredFrame::len`].
    fn length(&self) -> u16;
    fn payload(&self) -> &[u8];
    fn extended(&self) -> bool;
    fn fd(&self) -> bool;
    fn rtr(&self) -> bool;
    fn brs(&self) -> bool;
    fn esi(&self) -> bool;
    fn source_address(&self) -> Option<u16>;
    fn incomplete(&self) -> Option<bool>;
    fn direction(&self) -> Option<Direction>;
}

impl FrameRecord for StoredFrame {
    fn protocol(&self) -> &str {
        &self.protocol
    }
    fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }
    fn frame_id(&self) -> u32 {
        self.frame_id
    }
    fn bus(&self) -> u8 {
        self.bus
    }
    fn length(&self) -> u16 {
        self.len
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
    fn extended(&self) -> bool {
        self.extended
    }
    fn fd(&self) -> bool {
        self.fd
    }
    fn rtr(&self) -> bool {
        self.rtr
    }
    fn brs(&self) -> bool {
        self.brs
    }
    fn esi(&self) -> bool {
        self.esi
    }
    fn source_address(&self) -> Option<u16> {
        self.source_address
    }
    fn incomplete(&self) -> Option<bool> {
        self.incomplete
    }
    fn direction(&self) -> Option<Direction> {
        self.direction
    }
}

fn direction_text(direction: Direction) -> &'static str {
    match direction {
        Direction::Rx => "rx",
        Direction::Tx => "tx",
    }
}

/// Only `rx` and `tx` were ever written, so anything else reads as unknown.
fn parse_direction(text: &str) -> Option<Direction> {
    match text {
        "rx" => Some(Direction::Rx),
        "tx" => Some(Direction::Tx),
        _ => None,
    }
}

pub(crate) fn row_to_frame(row: &rusqlite::Row) -> rusqlite::Result<StoredFrame> {
    let payload: Vec<u8> = row.get("payload")?;
    Ok(StoredFrame {
        protocol: row.get("protocol")?,
        timestamp_us: row.get::<_, i64>("timestamp_us")? as u64,
        frame_id: row.get::<_, i64>("frame_id")? as u32,
        bus: row.get::<_, i64>("bus")? as u8,
        len: (row.get::<_, i64>("dlc")? as u16).max(payload.len() as u16),
        payload,
        extended: row.get("is_extended")?,
        fd: row.get("is_fd")?,
        rtr: row.get("is_rtr")?,
        brs: row.get("is_brs")?,
        esi: row.get("is_esi")?,
        source_address: row
            .get::<_, Option<i64>>("source_address")?
            .map(|v| v as u16),
        incomplete: row.get::<_, Option<i64>>("incomplete")?.map(|v| v != 0),
        direction: row
            .get::<_, Option<String>>("direction")?
            .as_deref()
            .and_then(parse_direction),
    })
}

pub(crate) fn row_to_frame_with_rowid(row: &rusqlite::Row) -> rusqlite::Result<(i64, StoredFrame)> {
    Ok((row.get("rowid")?, row_to_frame(row)?))
}

/// Append `frames` to a capture in one transaction.
pub fn insert_frames(
    conn: &mut Connection,
    capture_id: &str,
    frames: &[impl FrameRecord],
) -> Result<()> {
    if frames.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    insert_frame_rows(&tx, capture_id, frames)?;
    tx.commit()?;
    Ok(())
}

/// Replace a capture's frames with `frames` in one transaction; framing reuses a capture id.
pub fn clear_and_refill(
    conn: &mut Connection,
    capture_id: &str,
    frames: &[impl FrameRecord],
) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM frames WHERE capture_id = ?1",
        params![capture_id],
    )?;
    insert_frame_rows(&tx, capture_id, frames)?;
    tx.commit()?;
    Ok(())
}

fn insert_frame_rows(
    conn: &Connection,
    capture_id: &str,
    frames: &[impl FrameRecord],
) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    for f in frames {
        stmt.execute(params![
            capture_id,
            f.protocol(),
            f.timestamp_us() as i64,
            f.frame_id() as i64,
            f.bus() as i64,
            f.length() as i64,
            f.payload(),
            f.extended(),
            f.fd(),
            f.rtr(),
            f.brs(),
            f.esi(),
            f.source_address().map(i64::from),
            f.incomplete().map(i64::from),
            f.direction().map(direction_text),
        ])?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn can_frame(frame_id: u32, payload: &[u8]) -> StoredFrame {
    StoredFrame {
        protocol: "can".into(),
        frame_id,
        len: payload.len() as u16,
        payload: payload.to_vec(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::migrated;

    fn stored_rows(conn: &Connection) -> Vec<StoredFrame> {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {FRAME_COLUMNS} FROM frames ORDER BY rowid"
            ))
            .unwrap();
        stmt.query_map([], row_to_frame)
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[test]
    fn a_can_frame_round_trips_through_its_stored_row() {
        let frames = [
            CanFrame::data(1, 0x123, false, false, false, vec![1, 2, 3]),
            {
                let mut fd = CanFrame::data(0, 0x1ABCDEF, true, true, true, vec![0; 12]);
                fd.esi = true;
                fd
            },
            CanFrame::remote(2, 0x7FF, false, 6),
        ];
        for frame in frames {
            let stored = StoredFrame::can(42, &frame, Direction::Tx);
            assert_eq!(stored.to_can(), Some(frame.clone()));
            assert_eq!(stored.capture_protocol(), Some(CaptureProtocol::Can));
        }
        let remote = StoredFrame::can(0, &CanFrame::remote(0, 1, false, 6), Direction::Rx);
        assert_eq!((remote.len, remote.payload.len()), (6, 0));
    }

    #[test]
    fn only_a_can_row_is_a_can_frame() {
        let modbus = StoredFrame {
            protocol: "modbus".into(),
            ..can_frame(3, &[0, 1])
        };
        assert_eq!(modbus.to_can(), None);
        let unknown = StoredFrame {
            protocol: "lin".into(),
            ..can_frame(3, &[0, 1])
        };
    #[test]
    fn the_gateways_modbus_rtu_is_the_ingest_row_protocol() {
        assert_eq!(
            CaptureProtocol::ModbusRtu.as_str(),
            wiretap_protocol::ingest::MODBUS_RTU_PROTOCOL
        );
    }

        assert_eq!(unknown.capture_protocol(), None);
    }

    #[test]
    fn every_column_round_trips_through_an_insert() {
        let mut conn = migrated();
        let frames = [
            StoredFrame {
                protocol: "serial".into(),
                timestamp_us: 1_700_000_000_000_000,
                frame_id: 0x10,
                bus: 3,
                source_address: Some(0x0102),
                incomplete: Some(true),
                direction: Some(Direction::Rx),
                ..can_frame(0x10, &[0xAA, 0xBB])
            },
            StoredFrame {
                fd: true,
                brs: true,
                esi: true,
                extended: true,
                direction: Some(Direction::Tx),
                ..can_frame(0x1FFF_FFFF, &[7; 64])
            },
            StoredFrame {
                protocol: "future-protocol".into(),
                ..can_frame(9, &[])
            },
        ];

        insert_frames(&mut conn, "c1", &frames).unwrap();

        assert_eq!(stored_rows(&conn), frames);
        let directions: Vec<Option<String>> = conn
            .prepare("SELECT direction FROM frames ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(directions, [Some("rx".into()), Some("tx".into()), None]);
    }

    #[test]
    fn an_unknown_direction_reads_as_none() {
        let conn = migrated();
        conn.execute_batch(
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, direction)
             VALUES ('c1', 'can', 1, 1, 0, 0, x'', 'sideways')",
        )
        .unwrap();
        assert_eq!(stored_rows(&conn)[0].direction, None);
    }

    #[test]
    fn clearing_and_refilling_replaces_only_that_capture() {
        let mut conn = migrated();
        insert_frames(&mut conn, "c1", &[can_frame(1, &[1]), can_frame(2, &[2])]).unwrap();
        insert_frames(&mut conn, "c2", &[can_frame(3, &[3])]).unwrap();

        clear_and_refill(&mut conn, "c1", &[can_frame(4, &[4])]).unwrap();

        let ids: Vec<(String, u32)> = conn
            .prepare("SELECT capture_id, frame_id FROM frames ORDER BY rowid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(ids, [("c2".into(), 3), ("c1".into(), 4)]);
    }
}
