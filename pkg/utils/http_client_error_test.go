package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
