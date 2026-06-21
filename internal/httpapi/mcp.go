package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
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

// requireLeadSession returns the session iff the caller is an authenticated lead;
// otherwise it writes 401/403 and returns false.
func requireLeadSession(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return auth.Session{}, false
	}
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return auth.Session{}, false
	}
	return sess, true
}

func (s *Server) handleListMCPTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireLeadSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.MCPTokens.List())
}

func (s *Server) handleCreateMCPToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireLeadSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Label   string     `json:"label"`
		Role    auth.Role  `json:"role"`
		Expires *time.Time `json:"expires"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	full, rec, err := s.MCPTokens.Issue(body.Role, body.Label, body.Expires)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "token_create", Target: rec.ID, Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": full, "id": rec.ID, "role": string(rec.Role),
		"label": rec.Label, "created": rec.Created, "expires": rec.Expires,
	})
}

func (s *Server) handleRevokeMCPToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireLeadSession(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	revoked := s.MCPTokens.Revoke(id)
	result := "ok"
	if !revoked {
		result = "denied"
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "token_revoke", Target: id, Source: r.RemoteAddr, Result: result})
	if !revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such token"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
