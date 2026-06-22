package httpapi

import (
	"encoding/json"
	"net/http"
)

// mcpProtocolVersion is the MCP revision this server implements.
const mcpProtocolVersion = "2025-06-18"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternal       = -32603
)

func rpcErr(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
func rpcOK(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// handleMCP is the single MCP endpoint. requireMCPToken ran already; the token is in
// context. Decodes one JSON-RPC request and dispatches. Stateless JSON response (no SSE).
// Notifications (no id) get 202 with no body.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		// JSON-RPC 2.0 §5.1: when the id can't be detected (parse error), id MUST be null.
		writeJSON(w, http.StatusOK, rpcErr(json.RawMessage("null"), rpcParseError, "parse error"))
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSON(w, http.StatusOK, rpcErr(req.ID, rpcInvalidRequest, "invalid request"))
		return
	}
	if len(req.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, rpcOK(req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "passwordatthedisco-mcp", "version": s.Build.Version},
		}))
	case "ping":
		writeJSON(w, http.StatusOK, rpcOK(req.ID, map[string]any{}))
	case "tools/list":
		writeJSON(w, http.StatusOK, s.mcpToolsList(r, req))
	case "tools/call":
		writeJSON(w, http.StatusOK, s.mcpToolsCall(r, req))
	default:
		writeJSON(w, http.StatusOK, rpcErr(req.ID, rpcMethodNotFound, "method not found: "+req.Method))
	}
}
