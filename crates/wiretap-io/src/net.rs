//! Name resolution, and the TCP connect Modbus and GVRET share: the endpoint is
//! resolved on every connect, and each address it resolves to is tried within
//! one budget.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::net::{lookup_host, ToSocketAddrs};
#[cfg(any(feature = "modbus-tcp", feature = "can-gvret"))]
use tokio::{
    net::TcpStream,
    time::{timeout, timeout_at, Instant},
};

/// Each reason is short and single-line: consumers store it verbatim as a
/// health string or alarm text.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("cannot resolve {endpoint}: {reason}")]
    Resolve {
        endpoint: String,
        reason: ResolveError,
    },
    #[error("connect to {addr} failed: {source}")]
    Connect { addr: SocketAddr, source: io::Error },
    #[error("connect to {addr} timed out after {after:?}")]
    ConnectTimeout { addr: SocketAddr, after: Duration },
    #[error("timed out after {after:?}")]
    Timeout { after: Duration },
    #[error("connection failed: {0}")]
    Io(io::Error),
    #[error("connection closed by the device")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("{0}")]
    Io(io::Error),
    #[error("no addresses")]
    NoAddresses,
    #[error("timed out")]
    TimedOut,
}

/// `host:port` as an endpoint, an IPv6 literal bracketed.
pub fn tcp_endpoint(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::from((ip, port)).to_string(),
        Err(_) => format!("{host}:{port}"),
    }
}

/// Every address `host` (a name or an IP literal) resolves to on `port`,
/// through the system resolver; never empty on `Ok`.
pub async fn resolve(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, ResolveError> {
    tokio::time::timeout(timeout, lookup((host, port)))
        .await
        .unwrap_or(Err(ResolveError::TimedOut))
}

async fn lookup(target: impl ToSocketAddrs) -> Result<Vec<SocketAddr>, ResolveError> {
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .map_err(ResolveError::Io)?
        .collect();
    if addrs.is_empty() {
        return Err(ResolveError::NoAddresses);
    }
    Ok(addrs)
}

/// `connect_timeout` covers resolving and every address tried.
#[cfg(any(feature = "modbus-tcp", feature = "can-gvret"))]
pub(crate) async fn connect(
    endpoint: &str,
    connect_timeout: Duration,
) -> Result<TcpStream, TransportError> {
    let deadline = Instant::now() + connect_timeout;
    let resolve_failed = |reason| TransportError::Resolve {
        endpoint: endpoint.to_owned(),
        reason,
    };
    let addrs = timeout_at(deadline, lookup(endpoint))
        .await
        .unwrap_or(Err(ResolveError::TimedOut))
        .map_err(resolve_failed)?;
    connect_any(&addrs, deadline)
        .await
        .unwrap_or_else(|| Err(resolve_failed(ResolveError::NoAddresses)))
}

/// Each address gets an equal share of what is left of the budget, so one that
/// silently drops the SYN cannot starve the rest. `None` when there is nothing
/// to try.
#[cfg(any(feature = "modbus-tcp", feature = "can-gvret"))]
async fn connect_any(
    addrs: &[SocketAddr],
    deadline: Instant,
) -> Option<Result<TcpStream, TransportError>> {
    let mut last = None;
    for (i, &addr) in addrs.iter().enumerate() {
        let share = deadline.saturating_duration_since(Instant::now()) / (addrs.len() - i) as u32;
        let attempt = match timeout(share, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Some(Ok(stream)),
            Ok(Err(source)) => TransportError::Connect { addr, source },
            Err(_) => TransportError::ConnectTimeout {
                addr,
                after: Duration::from_millis(share.as_micros().div_ceil(1000) as u64),
            },
        };
        last = Some(Err(attempt));
    }
    last
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    use super::*;
    use support::{silent_addr, within};
    use tokio::net::TcpListener;

    async fn refused_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    fn deadline_in(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    #[tokio::test]
    async fn an_ip_literal_resolves_and_a_maximal_timeout_does_not_overflow() {
        let addrs = resolve("127.0.0.1", 8080, Duration::MAX).await;
        assert_eq!(addrs.unwrap(), ["127.0.0.1:8080".parse().unwrap()]);
    }

    /// `.invalid` is reserved (RFC 6761) and never resolves, so this exercises
    /// the system resolver without depending on the host's DNS.
    #[tokio::test]
    async fn an_unresolvable_name_is_a_resolve_error() {
        let err = resolve("wiretap-test.invalid", 23, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::Io(_) | ResolveError::NoAddresses),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_lookup_past_its_deadline_times_out() {
        let err = resolve("wiretap-test.invalid", 23, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::TimedOut), "{err:?}");
    }

    #[test]
    fn an_ipv6_host_is_bracketed_and_a_name_is_left_alone() {
        assert_eq!(tcp_endpoint("::1", 502), "[::1]:502");
        assert_eq!(tcp_endpoint("10.0.0.5", 502), "10.0.0.5:502");
        assert_eq!(tcp_endpoint("plc.local", 1502), "plc.local:1502");
    }

    #[tokio::test]
    async fn a_refused_address_falls_through_to_the_next() {
        within(async {
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addrs = [refused_addr().await, live.local_addr().unwrap()];
            let result = connect_any(&addrs, deadline_in(1000)).await;
            assert!(matches!(result, Some(Ok(_))));
        })
        .await
    }

    #[tokio::test]
    async fn the_last_failure_is_the_one_reported() {
        within(async {
            let addr = refused_addr().await;
            let result = connect_any(&[addr], deadline_in(1000)).await;
            assert!(
                matches!(result, Some(Err(TransportError::Connect { addr: a, .. })) if a == addr)
            );
            assert!(connect_any(&[], deadline_in(1000)).await.is_none());
        })
        .await
    }

    #[tokio::test]
    async fn a_silent_address_times_out_on_its_share_of_the_budget() {
        within(async {
            let (_guard, silent) = silent_addr().await;
            let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addrs = [silent, live.local_addr().unwrap()];
            let result = connect_any(&addrs, deadline_in(400)).await;
            assert!(matches!(result, Some(Ok(_))));

            let result = connect_any(&[silent], deadline_in(400)).await;
            assert!(
                matches!(result, Some(Err(TransportError::ConnectTimeout { addr, .. })) if addr == silent)
            );
        })
        .await
    }
}
