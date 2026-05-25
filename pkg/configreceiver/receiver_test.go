package configreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
)

const (
	pluginConfigID = "00000000-0000-0000-0000-000000000001"
	dhcpdConf      = "ddns-update-style none;"
)

// fakeServer captures REST traffic for one Receiver.Handle cycle so
// tests can assert on the apply report.
type fakeServer struct {
	*httptest.Server

	mu      sync.Mutex
	applied []map[string]any
}

func (fs *fakeServer) appliedCalls() []map[string]any {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]map[string]any, len(fs.applied))
	copy(out, fs.applied)
	return out
}

// newFakeServer builds an httptest.Server that responds to the two
// REST endpoints the Receiver depends on: the config GET and the
// applied POST. The handlerOverride lets a single test customise the
// GET response without re-writing the boilerplate.
func newFakeServer(t *testing.T, body string, statusOverride int, hashOverride string) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	hash := sha256hex(body)
	if hashOverride != "" {
		hash = hashOverride
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/plugins/configs/"+pluginConfigID+"/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if statusOverride != 0 {
				w.WriteHeader(statusOverride)
				_, _ = w.Write([]byte("forced error"))
				return
			}
			_ = json.NewEncoder(w).Encode(configResponse{
				ID:         pluginConfigID,
				PluginType: "dhcp",
				ServerID:   "server-uuid",
				Version:    7,
				ConfigHash: hash,
				ConfigText: body,
			})
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/api/plugins/configs/"+pluginConfigID+"/applied/", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fs.mu.Lock()
		fs.applied = append(fs.applied, payload)
		fs.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

func newReceiver(fs *fakeServer, applier Applier) *Receiver {
	return &Receiver{
		Session: &scheduler.Session{
			BaseURL:       fs.URL,
			Client:        fs.Client(),
			Authorization: `id="test-id", key="test-key"`,
		},
		Applier: applier,
	}
}

// recordingApplier captures the envelopes it was asked to apply and
// optionally returns a pre-canned error.
type recordingApplier struct {
	envelopes []Envelope
	err       error
}

func (r *recordingApplier) Apply(_ context.Context, env Envelope) error {
	r.envelopes = append(r.envelopes, env)
	return r.err
}

func envelopeJSON(t *testing.T, files map[string]string, metadata map[string]any) string {
	t.Helper()
	rawMeta := map[string]json.RawMessage{}
	for k, v := range metadata {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal metadata[%q]: %v", k, err)
		}
		rawMeta[k] = b
	}
	envBytes, err := json.Marshal(Envelope{Files: files, Metadata: rawMeta})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(envBytes)
}

func TestHandleSuccess(t *testing.T) {
	body := envelopeJSON(t, map[string]string{"dhcpd.conf": dhcpdConf}, nil)
	fs := newFakeServer(t, body, 0, "")
	applier := &recordingApplier{}
	r := newReceiver(fs, applier)

	r.Handle(context.Background(), pluginConfigID)

	if len(applier.envelopes) != 1 {
		t.Fatalf("expected 1 Apply call, got %d", len(applier.envelopes))
	}
	if got := applier.envelopes[0].Files["dhcpd.conf"]; got != dhcpdConf {
		t.Errorf("expected dhcpd.conf body, got %q", got)
	}
	calls := fs.appliedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 applied POST, got %d", len(calls))
	}
	if got := calls[0]["success"]; got != true {
		t.Errorf("expected success=true, got %v", got)
	}
	if got := calls[0]["applied_hash"]; got != sha256hex(body) {
		t.Errorf("applied_hash mismatch: %v", got)
	}
}

func TestHandleHashMismatchIsReported(t *testing.T) {
	body := envelopeJSON(t, map[string]string{"dhcpd.conf": dhcpdConf}, nil)
	fs := newFakeServer(t, body, 0, strings.Repeat("0", 64))
	applier := &recordingApplier{}
	r := newReceiver(fs, applier)

	r.Handle(context.Background(), pluginConfigID)

	if len(applier.envelopes) != 0 {
		t.Fatalf("Applier must not be called on hash mismatch")
	}
	calls := fs.appliedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 applied POST, got %d", len(calls))
	}
	if got := calls[0]["success"]; got != false {
		t.Errorf("expected success=false, got %v", got)
	}
	if got := calls[0]["error"]; got != "hash mismatch" {
		t.Errorf("expected hash mismatch error, got %v", got)
	}
}

func TestHandleEnvelopeDecodeFailureIsReported(t *testing.T) {
	body := "not-valid-json"
	fs := newFakeServer(t, body, 0, "")
	applier := &recordingApplier{}
	r := newReceiver(fs, applier)

	r.Handle(context.Background(), pluginConfigID)

	if len(applier.envelopes) != 0 {
		t.Fatal("Applier must not be called on envelope decode failure")
	}
	calls := fs.appliedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 applied POST, got %d", len(calls))
	}
	if got := calls[0]["success"]; got != false {
		t.Errorf("expected success=false, got %v", got)
	}
	errMsg, _ := calls[0]["error"].(string)
	if !strings.HasPrefix(errMsg, "envelope decode:") {
		t.Errorf("expected envelope decode error prefix, got %q", errMsg)
	}
}

func TestHandleApplierFailureIsReported(t *testing.T) {
	body := envelopeJSON(t, map[string]string{"dhcpd.conf": dhcpdConf}, nil)
	fs := newFakeServer(t, body, 0, "")
	applier := &recordingApplier{err: errors.New("dhcpd verification failed")}
	r := newReceiver(fs, applier)

	r.Handle(context.Background(), pluginConfigID)

	if len(applier.envelopes) != 1 {
		t.Fatal("Applier should be called even when it returns an error")
	}
	calls := fs.appliedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 applied POST, got %d", len(calls))
	}
	if got := calls[0]["success"]; got != false {
		t.Errorf("expected success=false, got %v", got)
	}
	if got := calls[0]["error"]; got != "dhcpd verification failed" {
		t.Errorf("expected applier's error string, got %v", got)
	}
}

func TestHandleFetchFailureIsReported(t *testing.T) {
	fs := newFakeServer(t, "", http.StatusInternalServerError, "")
	applier := &recordingApplier{}
	r := newReceiver(fs, applier)

	r.Handle(context.Background(), pluginConfigID)

	if len(applier.envelopes) != 0 {
		t.Fatal("Applier must not be called when fetch fails")
	}
	calls := fs.appliedCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 applied POST, got %d", len(calls))
	}
	if got := calls[0]["success"]; got != false {
		t.Errorf("expected success=false, got %v", got)
	}
	errMsg, _ := calls[0]["error"].(string)
	if !strings.HasPrefix(errMsg, "fetch failed:") {
		t.Errorf("expected fetch failure error prefix, got %q", errMsg)
	}
}

// Sanity check the local sha256hex helper against the stdlib so any
// drift between this and the server side is caught early.
func TestSha256HexMatchesStdlib(t *testing.T) {
	sum := sha256.Sum256([]byte(dhcpdConf))
	if expected := hex.EncodeToString(sum[:]); sha256hex(dhcpdConf) != expected {
		t.Fatalf("sha256hex drift")
	}
}

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		maxBytes int
		want     string
	}{
		{"under cap", "hello", 100, "hello"},
		{"exact cap", "hello", 5, "hello"},
		{"plain ASCII over cap", "abcdefghij", 5, "abcde...(truncated)"},
		// "한글" = 6 bytes (3+3). Cap=4 lands mid-codepoint; should
		// pull back to byte 3 (end of first rune).
		{"korean rune-aligned", "한글ABC", 4, "한...(truncated)"},
		// Cap exactly on the second rune boundary keeps both glyphs.
		{"korean exact rune boundary", "한글ABC", 6, "한글...(truncated)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := truncateUTF8(c.input, c.maxBytes)
			if got != c.want {
				t.Fatalf("truncateUTF8(%q, %d) = %q; want %q", c.input, c.maxBytes, got, c.want)
			}
		})
	}
}

// TestReportErrorTruncates verifies the on-wire error body is
// truncated at maxReportedErrorBytes and stays valid UTF-8 even when
// the truncation boundary would otherwise split a multi-byte rune.
func TestReportErrorTruncates(t *testing.T) {
	fs := newFakeServer(t, dhcpdConf, 0, "")
	r := newReceiver(fs, &recordingApplier{})

	// Build an error string longer than the cap. Include some 3-byte
	// Korean runes near the boundary to exercise the UTF-8 alignment.
	huge := strings.Repeat("X", maxReportedErrorBytes-2) + "한글" + strings.Repeat("Y", 100)
	r.reportError(pluginConfigID, huge)

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.applied) != 1 {
		t.Fatalf("expected 1 applied report, got %d", len(fs.applied))
	}
	gotErr, _ := fs.applied[0]["error"].(string)
	if !strings.HasSuffix(gotErr, "...(truncated)") {
		t.Fatalf("error not marked truncated: %q", gotErr)
	}
	if len(gotErr) > maxReportedErrorBytes+len("...(truncated)") {
		t.Fatalf("error too long: %d bytes", len(gotErr))
	}
	if !utf8.ValidString(gotErr) {
		t.Fatalf("truncated error is not valid UTF-8: %q", gotErr)
	}
}
