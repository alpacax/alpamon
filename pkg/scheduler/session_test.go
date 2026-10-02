package scheduler

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitSession_GivenConcurrentBursts_WhenSecondBurstFires_ThenIdleConnectionsAreReused(t *testing.T) {
	const burst = 8

	var newConns, arrived int32
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&arrived, 1) == burst {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	saved := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = saved })
	config.GlobalSettings = config.Settings{ServerURL: server.URL, SSLVerify: false, ID: "test", Key: "test"}
	session := InitSession()

	fire := func() {
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body, status, err := session.Get("/x", 10)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
				assert.Equal(t, "ok", string(body))
			}()
		}
		wg.Wait()
	}

	fire()
	require.Equal(t, int32(burst), atomic.LoadInt32(&newConns), "first burst opens one connection per request")

	atomic.StoreInt32(&arrived, burst) // later requests pass the barrier immediately
	fire()

	assert.Equal(t, int32(burst), atomic.LoadInt32(&newConns), "second burst must reuse the idle connections")
}
