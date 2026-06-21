package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// mcpTokenFrom returns the authenticated MCP token from the request context.
func mcpTokenFrom(ctx context.Context) (auth.APIToken, bool) {
	t, ok := ctx.Value(mcpTokenKey).(auth.APIToken)
	return t, ok
}

// requireMCPToken authenticates a bearer API token and attaches it to the context.
// Like requireIngestToken, but multi-token and role-bearing. Rate-limited per IP.
func (s *Server) requireMCPToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MCPTokens == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mcp access disabled"})
			return
		}
		ip := clientIP(r)
		if s.MCPLimiter != nil {
			if ok, retry := s.MCPLimiter.Allowed(ip); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts"})
				return
			}
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, ok := s.MCPTokens.Verify(raw)
		if !ok {
			if s.MCPLimiter != nil {
				s.MCPLimiter.RecordFailure(ip)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if s.MCPLimiter != nil {
			s.MCPLimiter.Reset(ip)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpTokenKey, tok)))
	})
}

// handleMCPWhoami returns the calling token's id + role. Proves the bearer auth path
// end-to-end. Does NOT require the data store to be unlocked.
func (s *Server) handleMCPWhoami(w http.ResponseWriter, r *http.Request) {
	tok, _ := mcpTokenFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"token_id": tok.ID, "role": string(tok.Role)})
}
