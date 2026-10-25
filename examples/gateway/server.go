package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Request is the body of POST /sessions.
//
// Admin is client-declared here, which is fine for a demo and wrong for
// anything real: a production gateway derives identity from authentication.
type Request struct {
	User    string   `json:"user"`
	Admin   bool     `json:"admin"`
	Host    string   `json:"host"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// Handler serves the demo HTTP API used by the OATS stack:
//
//	POST /sessions  open + authorize + exec; 403 on denial, trace ID in X-Trace-Id
//	GET  /healthz
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ctx, sess := g.Open(r.Context(), User{Name: req.User, Admin: req.Admin})
		defer sess.Close()
		w.Header().Set("X-Trace-Id", traceIDFrom(ctx))
		out, err := g.Run(ctx, sess, req.Host, req.Command, req.Args...)
		switch {
		case errors.Is(err, ErrDenied):
			http.Error(w, err.Error(), http.StatusForbidden)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			w.Write(out)
		}
	})
	return mux
}
