package junoscanhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type NotesFilterProxy struct {
	baseURL string
	server  *http.Server

	closeOnce sync.Once
	closeErr  error
}

func StartNotesFilterProxy(parent context.Context, upstreamBaseURL string) (*NotesFilterProxy, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(upstreamBaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("juno-scan notes filter proxy upstream URL is empty")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse juno-scan notes filter proxy upstream URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("parse juno-scan notes filter proxy upstream URL: invalid base URL %q", baseURL)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen juno-scan notes filter proxy: %w", err)
	}

	proxy := &NotesFilterProxy{
		baseURL: "http://" + listener.Addr().String(),
	}
	proxy.server = &http.Server{
		Handler:           newNotesFilterProxyHandler(baseURL, &http.Client{Timeout: 30 * time.Second}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-parent.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxy.Close(shutdownCtx)
	}()

	go func() {
		err := proxy.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = proxy.Close(context.Background())
		}
	}()

	return proxy, nil
}

func (p *NotesFilterProxy) BaseURL() string {
	if p == nil {
		return ""
	}
	return p.baseURL
}

func (p *NotesFilterProxy) Close(ctx context.Context) error {
	if p == nil || p.server == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closeErr = p.server.Shutdown(ctx)
	})
	return p.closeErr
}

func notesFilterProxyHandler(upstreamBaseURL string) http.Handler {
	return newNotesFilterProxyHandler(upstreamBaseURL, &http.Client{Timeout: 30 * time.Second})
}

func newNotesFilterProxyHandler(upstreamBaseURL string, client *http.Client) http.Handler {
	baseURL := strings.TrimRight(strings.TrimSpace(upstreamBaseURL), "/")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamURL := baseURL + r.URL.Path
		if rawQuery := strings.TrimSpace(r.URL.RawQuery); rawQuery != "" {
			upstreamURL += "?" + rawQuery
		}

		var body io.Reader
		if r.Body != nil {
			defer r.Body.Close()
			rawBody, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, fmt.Sprintf("read proxy request body: %v", err), http.StatusBadGateway)
				return
			}
			body = strings.NewReader(string(rawBody))
		}

		upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, body)
		if err != nil {
			http.Error(w, fmt.Sprintf("build proxy upstream request: %v", err), http.StatusBadGateway)
			return
		}
		upstreamReq.Header = r.Header.Clone()

		resp, err := client.Do(upstreamReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("proxy upstream request: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		rawResp, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("read proxy upstream response: %v", err), http.StatusBadGateway)
			return
		}

		if resp.StatusCode == http.StatusOK && isWalletNotesPath(r.URL.Path) {
			filtered, err := filterWalletNotesResponse(rawResp)
			if err != nil {
				http.Error(w, fmt.Sprintf("filter wallet notes response: %v", err), http.StatusBadGateway)
				return
			}
			rawResp = filtered
		}

		for key, values := range resp.Header {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(rawResp)
	})
}

func isWalletNotesPath(path string) bool {
	return strings.HasPrefix(path, "/v1/wallets/") && strings.HasSuffix(path, "/notes")
}

func filterWalletNotesResponse(raw []byte) ([]byte, error) {
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	notesRaw, ok := resp["notes"]
	if !ok {
		return raw, nil
	}

	var notes []json.RawMessage
	if err := json.Unmarshal(notesRaw, &notes); err != nil {
		return nil, err
	}

	filtered := make([]json.RawMessage, 0, len(notes))
	for _, noteRaw := range notes {
		keep, err := shouldKeepWalletNote(noteRaw)
		if err != nil {
			return nil, err
		}
		if keep {
			filtered = append(filtered, noteRaw)
		}
	}

	reencodedNotes, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	resp["notes"] = reencodedNotes
	return json.Marshal(resp)
}

func shouldKeepWalletNote(raw json.RawMessage) (bool, error) {
	var note struct {
		Direction *string `json:"direction"`
	}
	if err := json.Unmarshal(raw, &note); err != nil {
		return false, err
	}
	if note.Direction == nil {
		return true, nil
	}
	return strings.ToLower(strings.TrimSpace(*note.Direction)) != "outgoing", nil
}
