use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_CLIENTS: usize = 4096;
const MAX_REPORTS_PER_WINDOW: usize = 5;
const WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_FAILURES: usize = 10;
const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_LOGIN_CLIENTS: usize = 4096;

#[derive(Default)]
struct ClientWindow {
    accepted_requests: VecDeque<Instant>,
    last_block_event: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitResult {
    Allowed,
    Limited {
        retry_after_seconds: u64,
        record_security_event: bool,
    },
}

/// Per-process, per-IP request limiter for public occurrence submissions.
#[derive(Clone, Default)]
pub struct ReportRateLimiter {
    windows: Arc<Mutex<HashMap<IpAddr, ClientWindow>>>,
    blocked_requests: Arc<AtomicU64>,
}

#[derive(Clone, Default)]
pub struct LoginAttemptLimiter {
    failures: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
}

impl LoginAttemptLimiter {
    pub fn retry_after(&self, client_ip: IpAddr) -> Option<u64> {
        let now = Instant::now();
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        failures.retain(|_, attempts| {
            while attempts
                .front()
                .is_some_and(|time| now.duration_since(*time) >= LOGIN_WINDOW)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        let attempts = failures.get(&client_ip)?;
        if attempts.len() < LOGIN_MAX_FAILURES {
            return None;
        }
        let oldest = *attempts.front()?;
        Some(
            LOGIN_WINDOW
                .saturating_sub(now.duration_since(oldest))
                .as_secs()
                .max(1),
        )
    }

    pub fn record_failure(&self, client_ip: IpAddr) {
        let now = Instant::now();
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !failures.contains_key(&client_ip)
            && failures.len() >= MAX_LOGIN_CLIENTS
            && let Some(oldest_ip) = failures.keys().next().copied()
        {
            failures.remove(&oldest_ip);
        }
        let attempts = failures.entry(client_ip).or_default();
        while attempts
            .front()
            .is_some_and(|time| now.duration_since(*time) >= LOGIN_WINDOW)
        {
            attempts.pop_front();
        }
        attempts.push_back(now);
    }

    pub fn clear(&self, client_ip: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&client_ip);
    }
}

impl ReportRateLimiter {
    pub const fn max_requests_per_window() -> usize {
        MAX_REPORTS_PER_WINDOW
    }

    pub const fn window_seconds() -> u64 {
        WINDOW.as_secs()
    }

    pub fn check(&self, client_ip: IpAddr) -> RateLimitResult {
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        windows.retain(|_, client_window| {
            while client_window
                .accepted_requests
                .front()
                .is_some_and(|timestamp| now.duration_since(*timestamp) >= WINDOW)
            {
                client_window.accepted_requests.pop_front();
            }

            !client_window.accepted_requests.is_empty()
        });

        if !windows.contains_key(&client_ip)
            && windows.len() >= MAX_CLIENTS
            && let Some(oldest_ip) = windows.keys().next().copied()
        {
            windows.remove(&oldest_ip);
        }

        let client_window = windows.entry(client_ip).or_default();
        if client_window.accepted_requests.len() >= MAX_REPORTS_PER_WINDOW {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
            let oldest_request = *client_window
                .accepted_requests
                .front()
                .expect("a full rate-limit window contains a request");
            let seconds_remaining = WINDOW
                .saturating_sub(now.duration_since(oldest_request))
                .as_secs()
                .max(1);
            let record_security_event = client_window
                .last_block_event
                .is_none_or(|last_event| now.duration_since(last_event) >= WINDOW);
            if record_security_event {
                client_window.last_block_event = Some(now);
            }

            RateLimitResult::Limited {
                retry_after_seconds: seconds_remaining,
                record_security_event,
            }
        } else {
            client_window.accepted_requests.push_back(now);
            RateLimitResult::Allowed
        }
    }

    pub fn blocked_request_count(&self) -> u64 {
        self.blocked_requests.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_requests_per_ip_and_counts_every_rejected_attempt() {
        let limiter = ReportRateLimiter::default();
        let client_ip = IpAddr::from([192, 0, 2, 10]);

        for _ in 0..ReportRateLimiter::max_requests_per_window() {
            assert_eq!(limiter.check(client_ip), RateLimitResult::Allowed);
        }

        assert!(matches!(
            limiter.check(client_ip),
            RateLimitResult::Limited {
                retry_after_seconds: 1..=60,
                record_security_event: true
            }
        ));
        assert!(matches!(
            limiter.check(client_ip),
            RateLimitResult::Limited {
                retry_after_seconds: 1..=60,
                record_security_event: false
            }
        ));
        assert_eq!(limiter.blocked_request_count(), 2);
        assert_eq!(
            limiter.check(IpAddr::from([192, 0, 2, 11])),
            RateLimitResult::Allowed
        );
    }
}
