//! An HTTP client for the gateway, behind the `client` feature.
//!
//! It needs a tokio runtime to run on, and brings no TLS: a consumer enables
//! reqwest's `rustls-tls` or `native-tls` itself.

mod admin;
mod db;
mod frames;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{DatabaseList, ErrorBody, Health, RequestError};

pub use admin::AssignOutcome;
pub use db::Db;
pub use frames::{ArchiveFrame, FrameCursor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The request never got an answer; the cause chain, as text.
    Transport(String),
    /// A non-2xx answer, with the body's `error` when it had one.
    Status {
        code: u16,
        error: Option<String>,
    },
    Decode(String),
    Request(RequestError),
    BadHex(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(cause) => write!(f, "API request failed: {cause}"),
            Self::Status {
                error: Some(error), ..
            } => f.write_str(error),
            Self::Status { code, error: None } => match reqwest::StatusCode::from_u16(*code) {
                Ok(status) => write!(f, "HTTP {status}"),
                Err(_) => write!(f, "HTTP {code}"),
            },
            Self::Decode(cause) => write!(f, "API response decode failed: {cause}"),
            Self::Request(e) => e.fmt(f),
            Self::BadHex(data_hex) => write!(f, "bad data_hex '{data_hex}'"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<RequestError> for ClientError {
    fn from(e: RequestError) -> Self {
        Self::Request(e)
    }
}

/// `reqwest::Error` displays as "error sending request" and keeps refused,
/// reset or timed out for `source()`.
fn cause_chain(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Without one an unroutable gateway waits out the OS default, which is minutes.
    pub connect_timeout: Option<Duration>,
}

/// A query in flight, for a status log.
#[derive(Debug, Clone)]
pub struct RunningQuery {
    pub path: String,
    pub label: String,
    pub started_at: Instant,
}

/// The key stays out of [`RunningQuery`] so a status log cannot print it.
struct InFlight {
    endpoint: Endpoint,
    query: RunningQuery,
}

#[derive(Clone)]
struct Endpoint {
    base_url: String,
    api_key: String,
}

impl Endpoint {
    fn new(base_url: &str, api_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        }
    }
}

type Registry = Arc<Mutex<HashMap<String, InFlight>>>;

/// One gateway's client. Clones, and those from [`with_endpoint`](Self::with_endpoint),
/// share one connection pool and one registry of running queries.
#[derive(Clone)]
pub struct GatewayClient {
    http: reqwest::Client,
    endpoint: Endpoint,
    label: String,
    running: Registry,
}

impl fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient")
            .field("base_url", &self.endpoint.base_url)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl GatewayClient {
    /// An empty `api_key` sends no `Authorization` header.
    pub fn new(base_url: &str, api_key: &str, options: ClientOptions) -> Result<Self, ClientError> {
        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = options.connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|e| ClientError::Transport(cause_chain(&e)))?,
            endpoint: Endpoint::new(base_url, api_key),
            label: String::new(),
            running: Registry::default(),
        })
    }

    /// Another gateway, on this client's pool and running-query registry.
    pub fn with_endpoint(&self, base_url: &str, api_key: &str) -> Self {
        Self {
            endpoint: Endpoint::new(base_url, api_key),
            ..self.clone()
        }
    }

    /// The caller's name for this client's queries in [`running`](Self::running).
    pub fn with_label(&self, label: &str) -> Self {
        Self {
            label: label.to_string(),
            ..self.clone()
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let request = self
            .http
            .request(method, format!("{}{path}", self.endpoint.base_url));
        match self.endpoint.api_key.as_str() {
            "" => request,
            key => request.bearer_auth(key),
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        decode(send(self.request(reqwest::Method::GET, path)).await?).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, ClientError> {
        decode(send(self.request(reqwest::Method::POST, path).json(body)).await?).await
    }

    /// `GET /v1/health`, which takes no key.
    pub async fn health(&self) -> Result<Health, ClientError> {
        let url = format!("{}/v1/health", self.endpoint.base_url);
        decode(send(self.http.get(url)).await?).await
    }

    pub async fn databases(&self) -> Result<DatabaseList, ClientError> {
        self.get("/v1/databases").await
    }

    /// Needs an admin key.
    pub async fn create_database(&self, name: &str) -> Result<(), ClientError> {
        #[derive(Serialize)]
        struct NewDatabase<'a> {
            name: &'a str,
        }
        self.post::<serde::de::IgnoredAny>("/v1/databases", &NewDatabase { name })
            .await
            .map(drop)
    }

    /// POSTs a query, listed in [`running`](Self::running) under `query_id`
    /// until it answers or is dropped.
    pub async fn query<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        query_id: &str,
    ) -> Result<T, ClientError> {
        let _listed = Listed::new(self, path, query_id);
        self.post(path, body).await
    }

    pub fn running(&self) -> Vec<(String, RunningQuery)> {
        lock(&self.running)
            .iter()
            .map(|(id, q)| (id.clone(), q.query.clone()))
            .collect()
    }

    /// `DELETE /v1/queries/{id}` on the gateway running it; false for an id not
    /// running. The answer to the DELETE is not waited on for an error.
    pub async fn cancel(&self, query_id: &str) -> bool {
        let Some(endpoint) = lock(&self.running).remove(query_id).map(|q| q.endpoint) else {
            return false;
        };
        let _ = self
            .with_endpoint(&endpoint.base_url, &endpoint.api_key)
            .request(reqwest::Method::DELETE, &format!("/v1/queries/{query_id}"))
            .send()
            .await;
        true
    }
}

fn lock(running: &Registry) -> std::sync::MutexGuard<'_, HashMap<String, InFlight>> {
    running
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A query's place in the registry, given up when the query ends or is dropped.
struct Listed<'a> {
    running: &'a Registry,
    query_id: &'a str,
}

impl<'a> Listed<'a> {
    fn new(client: &'a GatewayClient, path: &str, query_id: &'a str) -> Self {
        lock(&client.running).insert(
            query_id.to_string(),
            InFlight {
                endpoint: client.endpoint.clone(),
                query: RunningQuery {
                    path: path.to_string(),
                    label: client.label.clone(),
                    started_at: Instant::now(),
                },
            },
        );
        Self {
            running: &client.running,
            query_id,
        }
    }
}

impl Drop for Listed<'_> {
    fn drop(&mut self) {
        lock(self.running).remove(self.query_id);
    }
}

/// The answer, whatever its status.
async fn answer(request: reqwest::RequestBuilder) -> Result<reqwest::Response, ClientError> {
    request
        .send()
        .await
        .map_err(|e| ClientError::Transport(cause_chain(&e)))
}

/// The answer if it is a success, else its status and `error` text.
async fn send(request: reqwest::RequestBuilder) -> Result<reqwest::Response, ClientError> {
    let response = answer(request).await?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    Err(refusal(status, &response.bytes().await.unwrap_or_default()))
}

fn refusal(status: reqwest::StatusCode, body: &[u8]) -> ClientError {
    ClientError::Status {
        code: status.as_u16(),
        error: serde_json::from_slice::<ErrorBody>(body)
            .ok()
            .map(|b| b.error),
    }
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ClientError> {
    response
        .json()
        .await
        .map_err(|e| ClientError::Decode(cause_chain(&e)))
}
