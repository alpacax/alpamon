package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPut_ErrorNamesOnlyTheHost(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	_, _, err := Put(closedURL+"/bucket/secret-path?X-Amz-Signature=secret-sig", strings.NewReader("x"), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), strings.TrimPrefix(closedURL, "http://"))
	assert.NotContains(t, err.Error(), "secret")
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	maxWait := time.Hour
	assert.Equal(t, 120*time.Second, ParseRetryAfter("120", now, maxWait))
	assert.Equal(t, 30*time.Second, ParseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now, maxWait))
	assert.Zero(t, ParseRetryAfter("", now, maxWait))
	assert.Zero(t, ParseRetryAfter("soon", now, maxWait))
	assert.Zero(t, ParseRetryAfter("-5", now, maxWait))
	assert.Zero(t, ParseRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now, maxWait))
	assert.Equal(t, maxWait, ParseRetryAfter("86400", now, maxWait), "a huge value must not stall a caller for a day")
}
