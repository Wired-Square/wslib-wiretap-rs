use std::ops::Deref;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::Connection;
use wiretap_analysis::order::TimedFrame;
use wiretap_analysis::source::{
    FrameSelection, FrameSource, InventoryRow, PayloadQuery, PayloadSource, Sampling, Source,
    SourceFrame,
};
use wiretap_analysis::FrameKey;

use crate::error::{CaptureError, Result};
use crate::frames::StoredFrame;
use crate::inventory::frame_inventory;
use crate::read::{get_frames_paginated_filtered, get_frames_tail_filtered, get_frames_tail_rows};
use crate::sample::{sample_frame_payloads, tail_frame_payloads};

/// Frames read a page at a time, so a whole capture is never one query.
const FRAME_PAGE: usize = 50_000;

/// One capture as the analysis levers read it, over `&Mutex<Connection>` or an
/// owned holder such as `Arc<Mutex<Connection>>`. Each read holds the lock for its
/// whole run, on the calling thread: an async caller moves it off the runtime.
pub struct CaptureSource<C> {
    pub conn: C,
    pub id: String,
}

impl<C: Deref<Target = Mutex<Connection>>> CaptureSource<C> {
    /// A poisoned lock still guards a usable connection: SQLite rolled back whatever the panic interrupted.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn selected(
        &self,
        selection: &FrameSelection,
        newest: Option<usize>,
    ) -> Result<Vec<StoredFrame>> {
        let conn = self.conn();
        match newest {
            Some(n) if selection.is_empty() => Ok(get_frames_tail_rows(&conn, &self.id, n)?.0),
            Some(n) => Ok(get_frames_tail_filtered(&conn, &self.id, n, selection)?.0),
            None => {
                let mut frames = Vec::new();
                loop {
                    let (page, _, total) = get_frames_paginated_filtered(
                        &conn,
                        &self.id,
                        frames.len(),
                        FRAME_PAGE,
                        selection,
                    )?;
                    let done = page.is_empty() || frames.len() + page.len() >= total;
                    frames.extend(page);
                    if done {
                        return Ok(frames);
                    }
                }
            }
        }
    }
}

fn source_frame(f: StoredFrame) -> SourceFrame {
    SourceFrame {
        frame: TimedFrame {
            bus: f.bus,
            key: FrameKey::new(f.frame_id, f.extended),
            timestamp_us: f.timestamp_us,
            payload: f.payload,
        },
        protocol: f.protocol,
    }
}

impl<C: Deref<Target = Mutex<Connection>> + Sync> Source for CaptureSource<C> {
    type Error = CaptureError;
}

impl<C: Deref<Target = Mutex<Connection>> + Sync> PayloadSource for CaptureSource<C> {
    async fn inventory(
        &self,
        start_us: Option<i64>,
        end_us: Option<i64>,
    ) -> Result<Vec<InventoryRow>> {
        frame_inventory(&self.conn(), &self.id, start_us, end_us)
    }

    async fn payloads(&self, q: PayloadQuery<'_>) -> Result<Vec<Vec<u8>>> {
        let read = match q.sampling {
            Sampling::Spread => sample_frame_payloads,
            Sampling::Recent => tail_frame_payloads,
        };
        read(
            &self.conn(),
            &self.id,
            q.protocol,
            q.frame_id,
            q.is_extended,
            q.limit,
        )
    }
}

impl<C: Deref<Target = Mutex<Connection>> + Sync> FrameSource for CaptureSource<C> {
    async fn frames(
        &self,
        selection: &FrameSelection,
        newest: Option<usize>,
    ) -> Result<Vec<SourceFrame>> {
        Ok(self
            .selected(selection, newest)?
            .into_iter()
            .map(source_frame)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::{multi_protocol_capture, whole};

    fn source_of(conn: &Mutex<Connection>) -> CaptureSource<&Mutex<Connection>> {
        CaptureSource {
            conn,
            id: "c1".into(),
        }
    }

    fn summary(frames: &[SourceFrame]) -> Vec<(&str, u32, u64)> {
        frames
            .iter()
            .map(|f| {
                (
                    f.protocol.as_str(),
                    f.frame.key.frame_id,
                    f.frame.timestamp_us,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn an_owned_source_reads_on_a_blocking_thread() {
        let source = CaptureSource {
            conn: std::sync::Arc::new(Mutex::new(multi_protocol_capture())),
            id: "c1".to_string(),
        };
        let frames = tokio::task::spawn_blocking(move || {
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            use std::future::Future;
            let can = whole("can");
            let mut read = std::pin::pin!(source.frames(&can, None));
            match read.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(frames) => frames.unwrap(),
                std::task::Poll::Pending => unreachable!("a capture read never waits"),
            }
        })
        .await
        .unwrap();
        assert_eq!(summary(&frames), [("can", 256, 10), ("can", 257, 40)]);
    }

    #[tokio::test]
    async fn frames_are_the_selection_oldest_first_or_its_newest() {
        let conn = Mutex::new(multi_protocol_capture());
        let source = source_of(&conn);

        let all = source
            .frames(&FrameSelection::default(), None)
            .await
            .unwrap();
        assert_eq!(
            summary(&all),
            [
                ("can", 256, 10),
                ("modbus", 256, 20),
                ("serial", 256, 30),
                ("can", 257, 40)
            ]
        );

        let can = source.frames(&whole("can"), None).await.unwrap();
        assert_eq!(summary(&can), [("can", 256, 10), ("can", 257, 40)]);

        let newest = source
            .frames(&FrameSelection::default(), Some(2))
            .await
            .unwrap();
        assert_eq!(summary(&newest), [("serial", 256, 30), ("can", 257, 40)]);

        let newest_can = source.frames(&whole("can"), Some(1)).await.unwrap();
        assert_eq!(summary(&newest_can), [("can", 257, 40)]);
    }

    #[tokio::test]
    async fn payloads_follow_the_sampling_and_the_inventory_the_window() {
        let conn = Mutex::new(multi_protocol_capture());
        let source = source_of(&conn);
        let query = |sampling| PayloadQuery {
            protocol: Some("modbus"),
            frame_id: 256,
            is_extended: None,
            limit: 10,
            sampling,
        };

        assert_eq!(
            source.payloads(query(Sampling::Spread)).await.unwrap(),
            [[0xBB]]
        );
        assert_eq!(
            source.payloads(query(Sampling::Recent)).await.unwrap(),
            [[0xBB]]
        );
        let rows = source.inventory(Some(30), None).await.unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| (r.protocol.as_str(), r.frame_id))
                .collect::<Vec<_>>(),
            [("serial", 256), ("can", 257)]
        );
    }

    #[tokio::test]
    async fn the_byte_profile_lever_reads_a_capture() {
        let conn = Mutex::new(multi_protocol_capture());

        let profile =
            wiretap_analysis::source::byte_profile(&source_of(&conn), Some("can"), 257, None, 10)
                .await
                .unwrap();

        assert_eq!(
            (profile.frame_id, profile.protocol.as_deref()),
            (257, Some("can"))
        );
    }
}
