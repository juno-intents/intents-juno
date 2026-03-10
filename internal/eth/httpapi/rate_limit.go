package httpapi

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type clientRateLimiter struct {
	mu sync.Mutex

	refillPerSecond float64
	burst           float64
	maxTracked      int
	states          map[string]clientLimiterState
}

type clientLimiterState struct {
	tokens   float64
	lastAt   time.Time
	lastSeen time.Time
}

func newClientRateLimiter(refillPerSecond float64, burst int, maxTracked int) *clientRateLimiter {
	if refillPerSecond <= 0 || burst <= 0 || maxTracked <= 0 {
		return nil
	}
	return &clientRateLimiter{
		refillPerSecond: refillPerSecond,
		burst:           float64(burst),
		maxTracked:      maxTracked,
		states:          make(map[string]clientLimiterState),
	}
}

func (l *clientRateLimiter) Allow(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	if key == "" {
		key = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	st, ok := l.states[key]
	if !ok {
		if len(l.states) >= l.maxTracked {
			l.evictOneLocked()
		}
		l.states[key] = clientLimiterState{
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
		l.states[key] = st
		return false
	}
	st.tokens -= 1
	l.states[key] = st
	return true
}

func (l *clientRateLimiter) evictOneLocked() {
	var (
		oldestKey string
		oldestAt  time.Time
		first     = true
	)
	for key, st := range l.states {
		if first || st.lastSeen.Before(oldestAt) {
			oldestKey = key
			oldestAt = st.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(l.states, oldestKey)
	}
}

func clientKey(r *http.Request, bearerToken string) string {
	if bearerToken != "" {
		return "token:" + bearerToken
	}
	return "ip:" + extractClientIP(r)
}

// extractClientIP uses only the direct remote address. The Base NLB preserves
// the client IP at L4, and trusting forwarded headers would allow bypasses.
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
	if idx := strings.LastIndex(remote, ":"); idx > 0 {
		host = remote[:idx]
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.String()
	}
	return remote
}
