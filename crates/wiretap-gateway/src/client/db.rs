use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{decode, send, ClientError, FrameCursor, GatewayClient};
use crate::request::{query_string, wire};
use crate::{
    DatabaseActivityResult, Event, EventPatch, EventsResponse, FrameFilter, FramesQuery,
    ImportResult, InventoryEntry, InventoryResponse, NewEvent, PayloadsParams, PayloadsResponse,
    Protocol, SignalResponse, TimeBounds, TimeRangeQuery,
};

/// One database on the gateway, read as one protocol: every request here
/// carries `protocol`, whatever the query passed in names.
#[derive(Debug, Clone)]
pub struct Db<'a> {
    client: &'a GatewayClient,
    prefix: String,
    protocol: Protocol,
}

impl GatewayClient {
    pub fn db(&self, name: &str, protocol: Protocol) -> Db<'_> {
        Db {
            client: self,
            prefix: format!("/v1/db/{name}"),
            protocol,
        }
    }
}

impl Db<'_> {
    fn path(&self, path: &str) -> String {
        format!("{}{path}", self.prefix)
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client.request(method, &self.path(path))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        decode(send(self.request(Method::GET, path)).await?).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, ClientError> {
        decode(send(self.request(Method::POST, path).json(body)).await?).await
    }

    /// [`GatewayClient::query`] on a path relative to the database, such as a
    /// [`GatewayRequest`](crate::GatewayRequest)'s.
    pub async fn query<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        query_id: &str,
    ) -> Result<T, ClientError> {
        self.client.query(&self.path(path), body, query_id).await
    }

    /// The entries and whether they were cut, by the gateway or here at `limit`
    /// for a gateway that ignores it.
    pub async fn inventory(
        &self,
        query: TimeRangeQuery,
    ) -> Result<(Vec<InventoryEntry>, bool), ClientError> {
        let query = TimeRangeQuery {
            protocol: wire(self.protocol),
            ..query
        };
        let InventoryResponse {
            mut entries,
            truncated,
        } = self.get(&query.inventory_path()).await?;
        let limit = query.limit.map_or(usize::MAX, |n| n as usize);
        let cut = entries.len() > limit;
        entries.truncate(limit);
        Ok((entries, truncated || cut))
    }

    /// Oldest first; the gateway answers newest first.
    pub async fn payloads(
        &self,
        filter: FrameFilter,
        limit: u32,
    ) -> Result<Vec<Vec<u8>>, ClientError> {
        let body = PayloadsParams {
            filter: FrameFilter {
                protocol: wire(self.protocol),
                ..filter
            },
            limit: Some(limit),
        };
        let PayloadsResponse { mut payloads } = self.post("/payloads", &body).await?;
        payloads.reverse();
        Ok(payloads)
    }

    pub async fn time_bounds(&self) -> Result<TimeBounds, ClientError> {
        let protocol = wire(self.protocol).map(|p| p.as_str().into());
        self.get(&format!(
            "/time-bounds{}",
            query_string(&[("protocol", protocol)])
        ))
        .await
    }

    /// Every event; the gateway's default is the oldest 1000, with no cursor.
    pub async fn events_list(&self) -> Result<Vec<Event>, ClientError> {
        let EventsResponse { events } = self.get("/events?limit=1000000").await?;
        Ok(events)
    }

    pub async fn events_add(&self, event: &NewEvent) -> Result<Event, ClientError> {
        self.post("/events", event).await
    }

    pub async fn events_update(&self, id: i64, patch: &EventPatch) -> Result<Event, ClientError> {
        let request = self.request(Method::PATCH, &format!("/events/{id}"));
        decode(send(request.json(patch)).await?).await
    }

    /// The gateway answers 204, with no body.
    pub async fn events_delete(&self, id: i64) -> Result<(), ClientError> {
        send(self.request(Method::DELETE, &format!("/events/{id}")))
            .await
            .map(drop)
    }

    /// Posts one body of `wiretap_protocol::import` records; `create` makes the
    /// database first if it does not exist.
    pub async fn import(&self, body: Vec<u8>, create: bool) -> Result<ImportResult, ClientError> {
        let path = if create {
            "/import?create=true"
        } else {
            "/import"
        };
        let request = self
            .request(Method::POST, path)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-wiretap-frames",
            )
            .body(body);
        decode(send(request).await?).await
    }

    pub async fn activity(&self) -> Result<DatabaseActivityResult, ClientError> {
        self.get("/activity").await
    }

    /// Cancels a backend's query, or with `terminate` ends its session.
    pub async fn signal(&self, pid: i32, terminate: bool) -> Result<bool, ClientError> {
        let request = if terminate {
            self.request(Method::DELETE, &format!("/activity/{pid}"))
        } else {
            self.request(Method::POST, &format!("/activity/{pid}/cancel"))
        };
        let SignalResponse { ok } = decode(send(request).await?).await?;
        Ok(ok)
    }

    /// Pages through `/frames` from `query`'s bounds; its `after` starts the cursor.
    pub fn frames(&self, query: FramesQuery) -> FrameCursor {
        FrameCursor::new(
            self.client.clone(),
            self.path("/frames"),
            FramesQuery {
                protocol: wire(self.protocol),
                ..query
            },
        )
    }
}
