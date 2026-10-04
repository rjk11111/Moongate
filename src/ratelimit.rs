//! Sign-in rate limiting, stored in PostgreSQL so it holds across instances.
//!
//! Each attempt is counted atomically *before* OutlandsID is contacted, so parallel
//! requests cannot slip past the limit. Only rejected credentials accumulate.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderName;
use axum::http::request::Parts;
use sqlx::PgPool;

use crate::crypto;

pub const WINDOW_SECS: i64 = 15 * 60;
pub const MAX_ATTEMPTS_PER_EMAIL: i32 = 5;
pub const MAX_ATTEMPTS_PER_IP: i32 = 30;

/// The counters one sign-in attempt touches.
#[derive(Debug)]
pub struct Buckets {
    email: String,
    ip: Option<String>,
}

impl Buckets {
    pub fn new(email: &str, ip: Option<IpAddr>) -> Self {
        Self {
            email: format!(
                "email:{}",
                crypto::sha256_hex(&email.trim().to_ascii_lowercase())
            ),
            ip: ip.map(|ip| format!("ip:{}", ip_bucket(ip))),
        }
    }

    fn all(&self) -> Vec<&str> {
        std::iter::once(self.email.as_str())
            .chain(self.ip.as_deref())
            .collect()
    }
}

/// IPv6 clients usually control a whole /64, so count the prefix, not the address.
fn ip_bucket(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// Counts this attempt. Returns `true` if any bucket is now over its limit, in which
/// case the caller must not contact upstream.
// ponytail: fixed windows allow up to 2x the limit across a window boundary; switch to
// a sliding window if that matters.
pub async fn attempt(pool: &PgPool, buckets: &Buckets) -> sqlx::Result<bool> {
    let counts: Vec<(String, i32)> = sqlx::query_as(
        "INSERT INTO login_attempts (bucket, window_start, attempts) \
         SELECT b, date_bin(make_interval(secs => $2), now(), 'epoch'), 1 FROM unnest($1::text[]) b \
         ON CONFLICT (bucket, window_start) \
         DO UPDATE SET attempts = login_attempts.attempts + 1 \
         RETURNING bucket, attempts",
    )
    .bind(buckets.all())
    .bind(WINDOW_SECS as f64)
    .fetch_all(pool)
    .await?;

    // Opportunistic cleanup of finished windows.
    sqlx::query(
        "DELETE FROM login_attempts WHERE window_start < now() - make_interval(secs => $1)",
    )
    .bind((2 * WINDOW_SECS) as f64)
    .execute(pool)
    .await?;

    Ok(counts.iter().any(|(bucket, attempts)| {
        let limit = if bucket.starts_with("email:") {
            MAX_ATTEMPTS_PER_EMAIL
        } else {
            MAX_ATTEMPTS_PER_IP
        };
        *attempts > limit
    }))
}

/// Gives an attempt back: on success, and when upstream was unavailable (an outage
/// must not lock users out). Only rejected credentials accumulate.
pub async fn release(pool: &PgPool, buckets: &Buckets) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE login_attempts SET attempts = greatest(attempts - 1, 0) \
         WHERE bucket = ANY($1) \
           AND window_start = date_bin(make_interval(secs => $2), now(), 'epoch')",
    )
    .bind(buckets.all())
    .bind(WINDOW_SECS as f64)
    .execute(pool)
    .await?;
    Ok(())
}

/// The client address. With `trusted_header` unset, the TCP peer. With it set (for a
/// deployment behind a proxy that overwrites that header), the header's last entry,
/// falling back to the peer if it's missing or malformed. Only set it when every
/// request is guaranteed to pass through that proxy, or clients can spoof it.
pub fn client_ip(parts: &Parts, trusted_header: Option<&HeaderName>) -> Option<IpAddr> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let from_header = trusted_header
        .and_then(|name| parts.headers.get(name))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|last| last.trim().parse::<IpAddr>().ok());
    from_header.or(peer)
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;

    fn parts(peer: Option<&str>, headers: &[(&str, &str)]) -> Parts {
        let mut request = Request::get("/");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(()).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        request.into_parts().0
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn client_ip_uses_peer_unless_header_is_trusted() {
        let p = parts(Some("10.0.0.1:5000"), &[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(client_ip(&p, None), ip("10.0.0.1"));
        let xff = HeaderName::from_static("x-forwarded-for");
        assert_eq!(client_ip(&p, Some(&xff)), ip("203.0.113.9"));
    }

    #[test]
    fn trusted_header_takes_last_hop_and_falls_back_to_peer() {
        let xff = HeaderName::from_static("x-forwarded-for");
        let spoofed = parts(
            Some("10.0.0.1:5000"),
            &[("x-forwarded-for", "1.1.1.1, 203.0.113.9")],
        );
        assert_eq!(client_ip(&spoofed, Some(&xff)), ip("203.0.113.9"));
        let garbage = parts(Some("10.0.0.1:5000"), &[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_ip(&garbage, Some(&xff)), ip("10.0.0.1"));
        let missing = parts(Some("10.0.0.1:5000"), &[]);
        assert_eq!(client_ip(&missing, Some(&xff)), ip("10.0.0.1"));
        assert_eq!(client_ip(&parts(None, &[]), None), None);
    }

    #[test]
    fn ipv6_is_bucketed_by_64_and_mapped_v4_is_canonical() {
        assert_eq!(
            ip_bucket("2001:db8:1:2:aaaa::1".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            ip_bucket("2001:db8:1:2:aaaa::1".parse().unwrap()),
            ip_bucket("2001:db8:1:2:ffff::9".parse().unwrap())
        );
        assert_eq!(
            ip_bucket("::ffff:203.0.113.9".parse().unwrap()),
            "203.0.113.9"
        );
    }

    #[test]
    fn email_bucket_is_normalized_and_hashed() {
        let a = Buckets::new(" Player@Example.test ", None);
        let b = Buckets::new("player@example.test", None);
        assert_eq!(a.email, b.email);
        assert!(!a.email.contains("example"));
    }

    #[sqlx::test]
    async fn email_limit_blocks_after_max_attempts(pool: PgPool) {
        let buckets = Buckets::new("player@example.test", ip("203.0.113.9"));
        for _ in 0..MAX_ATTEMPTS_PER_EMAIL {
            assert!(!attempt(&pool, &buckets).await.unwrap());
        }
        assert!(attempt(&pool, &buckets).await.unwrap());
        // Another account from the same IP is unaffected.
        let other = Buckets::new("other@example.test", ip("203.0.113.9"));
        assert!(!attempt(&pool, &other).await.unwrap());
    }

    #[sqlx::test]
    async fn ip_limit_blocks_across_many_emails(pool: PgPool) {
        for i in 0..MAX_ATTEMPTS_PER_IP {
            let buckets = Buckets::new(&format!("user{i}@example.test"), ip("203.0.113.9"));
            assert!(!attempt(&pool, &buckets).await.unwrap());
        }
        let next = Buckets::new("fresh@example.test", ip("203.0.113.9"));
        assert!(attempt(&pool, &next).await.unwrap());
        let elsewhere = Buckets::new("fresh@example.test", ip("198.51.100.1"));
        assert!(!attempt(&pool, &elsewhere).await.unwrap());
    }

    #[sqlx::test]
    async fn successful_sign_ins_do_not_accumulate(pool: PgPool) {
        let buckets = Buckets::new("player@example.test", ip("203.0.113.9"));
        for _ in 0..(MAX_ATTEMPTS_PER_EMAIL * 3) {
            assert!(!attempt(&pool, &buckets).await.unwrap());
            release(&pool, &buckets).await.unwrap();
        }
    }

    #[sqlx::test]
    async fn concurrent_attempts_cannot_exceed_limit(pool: PgPool) {
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let buckets = Buckets::new("player@example.test", None);
                    attempt(&pool, &buckets).await.unwrap()
                })
            })
            .collect();
        let mut allowed = 0;
        for task in tasks {
            if !task.await.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, MAX_ATTEMPTS_PER_EMAIL);
    }

    #[sqlx::test]
    async fn old_windows_do_not_count(pool: PgPool) {
        let buckets = Buckets::new("player@example.test", None);
        for _ in 0..=MAX_ATTEMPTS_PER_EMAIL {
            attempt(&pool, &buckets).await.unwrap();
        }
        sqlx::query("UPDATE login_attempts SET window_start = window_start - interval '1 hour'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!attempt(&pool, &buckets).await.unwrap());
    }
}
