package backoffice

import (
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// authMiddleware checks the Authorization: Bearer <token> header against the
// configured auth secret. Probe endpoints, the dashboard UI, and static assets
// are exempt so the browser can load the page and prompt for a token.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for probes, dashboard root, and static assets.
		if isProbePath(r.URL.Path) || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AuthSecret)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies per-IP token bucket rate limiting.
// Probe endpoints are exempt.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	limiter := newBackofficeRateLimiter(
		s.cfg.RateLimitPerSecond,
		float64(s.cfg.RateLimitBurst),
		1000,
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for probes.
		if isProbePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractClientIP(r)
		if !limiter.Allow(ip, time.Now().UTC()) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// backofficeRateLimiter is a per-IP token bucket rate limiter with LRU eviction.
type backofficeRateLimiter struct {
	mu sync.Mutex

	refillPerSecond float64
	burst           float64
	maxTrackedIPs   int
	states          map[string]boLimiterState
}

type boLimiterState struct {
	tokens   float64
	lastAt   time.Time
	lastSeen time.Time
}

func newBackofficeRateLimiter(refillPerSecond float64, burst float64, maxTrackedIPs int) *backofficeRateLimiter {
	return &backofficeRateLimiter{
		refillPerSecond: refillPerSecond,
		burst:           burst,
		maxTrackedIPs:   maxTrackedIPs,
		states:          make(map[string]boLimiterState),
	}
}

func (l *backofficeRateLimiter) Allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	if ip == "" {
		ip = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	st, ok := l.states[ip]
	if !ok {
		if len(l.states) >= l.maxTrackedIPs {
			l.evictOne()
		}
		l.states[ip] = boLimiterState{
			tokens:   l.burst - 1,
			lastAt:   now,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(st.lastAt).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * l.refillPerSecond
		if st.tokens > l.burst {
			st.tokens = l.burst
		}
	}
	st.lastAt = now
	st.lastSeen = now

	if st.tokens < 1 {
		l.states[ip] = st
		return false
	}
	st.tokens -= 1
	l.states[ip] = st
	return true
}

func (l *backofficeRateLimiter) evictOne() {
	var oldestIP string
	var oldestAt time.Time
	first := true
	for ip, st := range l.states {
		if first || st.lastSeen.Before(oldestAt) {
			oldestIP = ip
			oldestAt = st.lastSeen
			first = false
		}
	}
	if oldestIP != "" {
		delete(l.states, oldestIP)
	}
}

// extractClientIP extracts the client IP from r.RemoteAddr only. We do not
// trust X-Forwarded-For or X-Real-IP because the NLB preserves the real
// client IP at L4, and trusting proxy headers allows rate-limit bypass.
func extractClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return "unknown"
	}
	if addr, err := netip.ParseAddrPort(remote); err == nil {
		return addr.Addr().String()
	}
	if addr, err := netip.ParseAddr(remote); err == nil {
		return addr.String()
	}
	host := remote
	if i := strings.LastIndex(remote, ":"); i > 0 {
		host = remote[:i]
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.String()
	}
	return remote
}
