use super::{ClientError, GatewayClient};
use crate::request::query_string;
use crate::{FrameBatch, FrameBatchRow, FramesQuery};

/// A `/frames` row with its payload decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFrame {
    pub ts_us: i64,
    pub id: u32,
    pub extended: bool,
    /// The payload's length, or for an RTR the length its code asks for: the
    /// row's `dlc` is a CAN length code, and a gateway before 0.1.4 serves no `len`.
    pub len: u16,
    pub data: Vec<u8>,
    pub is_fd: bool,
    pub is_rtr: bool,
    pub is_brs: bool,
    pub is_esi: bool,
    pub bus: u8,
    pub dir: String,
}

impl TryFrom<FrameBatchRow> for ArchiveFrame {
    type Error = ClientError;

    fn try_from(row: FrameBatchRow) -> Result<Self, ClientError> {
        let data = wiretap_decode::hex::parse_bytes(&row.data_hex)
            .map_err(|_| ClientError::BadHex(row.data_hex.clone()))?;
        let len = if row.is_rtr {
            wiretap_protocol::dlc_to_len(row.dlc as u8, false)
        } else {
            data.len()
        };
        Ok(Self {
            ts_us: row.ts_us,
            id: row.id,
            extended: row.extended,
            len: len as u16,
            data,
            is_fd: row.is_fd,
            is_rtr: row.is_rtr,
            is_brs: row.is_brs,
            is_esi: row.is_esi,
            bus: row.bus,
            dir: row.dir,
        })
    }
}

/// The `/frames` keyset cursor, a page at a time.
#[derive(Debug, Clone)]
pub struct FrameCursor {
    client: GatewayClient,
    path: String,
    query: FramesQuery,
    exhausted: bool,
    remaining: Option<usize>,
}

impl FrameCursor {
    pub(crate) fn new(client: GatewayClient, path: String, query: FramesQuery) -> Self {
        Self {
            client,
            path,
            query,
            exhausted: false,
            remaining: None,
        }
    }

    /// Stops after `frames` in all, across pages.
    pub fn at_most(self, frames: usize) -> Self {
        Self {
            remaining: Some(frames),
            ..self
        }
    }

    /// True once the gateway has no more pages or the [`at_most`](Self::at_most) total is reached.
    pub fn is_done(&self) -> bool {
        self.exhausted || self.remaining == Some(0)
    }

    /// The next page, empty once the cursor is spent.
    pub async fn next_page(&mut self) -> Result<Vec<ArchiveFrame>, ClientError> {
        if self.is_done() {
            return Ok(Vec::new());
        }
        let FrameBatch {
            frames,
            next_cursor,
        } = self.client.get(&self.url()).await?;
        self.exhausted = next_cursor.is_none();
        self.query.after = next_cursor;
        let mut frames = frames
            .into_iter()
            .map(ArchiveFrame::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(remaining) = &mut self.remaining {
            if frames.len() > *remaining {
                frames.truncate(*remaining);
                self.exhausted = true;
            }
            *remaining -= frames.len();
        }
        Ok(frames)
    }

    fn url(&self) -> String {
        let FramesQuery {
            start,
            end,
            after,
            limit,
            protocol,
        } = &self.query;
        let query = query_string(&[
            ("limit", limit.map(|n| n.to_string())),
            ("protocol", protocol.map(|p| p.as_str().into())),
            ("start", start.clone()),
            ("end", end.clone()),
            ("after", after.clone()),
        ]);
        format!("{}{query}", self.path)
    }
}
