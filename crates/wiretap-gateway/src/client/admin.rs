use reqwest::{Method, StatusCode};

use super::{answer, cause_chain, refusal, ClientError, GatewayClient};
use crate::request::{percent_encode, query_string};
use crate::{
    AssignCatalog, AssignedCatalog, AssignmentConflict, CatalogFinding, CatalogRejected,
    DaemonList, StoredCatalog, UnassignParams,
};

/// How the gateway answered a catalogue assignment or its removal.
#[derive(Debug, Clone, PartialEq)]
pub enum AssignOutcome {
    Done { warnings: Vec<CatalogFinding> },
    Rejected(CatalogRejected),
    Conflict(AssignmentConflict),
}

impl GatewayClient {
    /// Needs an admin key, as do the other admin methods.
    pub async fn daemons(&self) -> Result<DaemonList, ClientError> {
        self.get("/v1/admin/daemons").await
    }

    pub async fn stored_catalogue(&self, blob_sha: &str) -> Result<StoredCatalog, ClientError> {
        self.get(&format!("/v1/admin/catalogs/{}", percent_encode(blob_sha)))
            .await
    }

    pub async fn assign_catalogue(
        &self,
        assign: &AssignCatalog,
    ) -> Result<AssignOutcome, ClientError> {
        let request = self
            .request(Method::PUT, "/v1/admin/assignments")
            .json(assign);
        outcome(answer(request).await?).await
    }

    /// A 404, from a gateway whose `DELETE` is not yet idempotent, is `Done`.
    pub async fn unassign_catalogue(
        &self,
        params: &UnassignParams,
    ) -> Result<AssignOutcome, ClientError> {
        let query = query_string(&[
            ("daemon_id", Some(params.daemon_id.clone())),
            ("interface", Some(params.interface.clone())),
            ("expected", params.expected.clone()),
        ]);
        let request = self.request(Method::DELETE, &format!("/v1/admin/assignments{query}"));
        let response = answer(request).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(AssignOutcome::Done { warnings: vec![] });
        }
        outcome(response).await
    }
}

async fn outcome(response: reqwest::Response) -> Result<AssignOutcome, ClientError> {
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| ClientError::Decode(cause_chain(&e)))?;
    let outcome = match status {
        StatusCode::CONFLICT => serde_json::from_slice(&body)
            .ok()
            .map(AssignOutcome::Conflict),
        StatusCode::BAD_REQUEST => serde_json::from_slice(&body)
            .ok()
            .map(AssignOutcome::Rejected),
        s if s.is_success() && body.is_empty() => Some(AssignOutcome::Done { warnings: vec![] }),
        s if s.is_success() => {
            return serde_json::from_slice::<AssignedCatalog>(&body)
                .map(|a| AssignOutcome::Done {
                    warnings: a.warnings,
                })
                .map_err(|e| ClientError::Decode(e.to_string()));
        }
        _ => None,
    };
    outcome.ok_or_else(|| refusal(status, &body))
}
