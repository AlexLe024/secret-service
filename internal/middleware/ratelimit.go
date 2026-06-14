package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds per-IP token buckets.
type RateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*ipLimiter
	r          rate.Limit
	burst      int
	trustProxy bool
}

// NewRateLimiter creates a RateLimiter that allows r events per second with a
// burst of burst, tracked per client IP. Stale entries are cleaned up every minute.
//
// trustProxy controls how the client IP is derived: when true (the service runs
// behind a trusted reverse proxy/load balancer) the leftmost X-Forwarded-For
// address is used, so clients are not all collapsed into the proxy's single IP.
// When false the direct connection address is used, so a spoofed X-Forwarded-For
// header cannot be used to evade the limit.
func NewRateLimiter(r rate.Limit, burst int, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		limiters:   make(map[string]*ipLimiter),
		r:          r,
		burst:      burst,
		trustProxy: trustProxy,
	}
	go rl.cleanup()
	return rl
}

// clientIP resolves the key used for rate-limiting buckets.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	if rl.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (rl *RateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &ipLimiter{limiter: rate.NewLimiter(rl.r, rl.burst)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.limiters {
			if time.Since(entry.lastSeen) > 5*time.Minute {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit returns an HTTP middleware that enforces the rate limit per client IP.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)
		if !rl.get(ip).Allow() {
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
