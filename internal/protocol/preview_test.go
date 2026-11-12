package protocol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreview_KeepsShortInputAndCutsLongInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"short", `{"query":`, `{"query":`},
		{"exactly the preview size", strings.Repeat("x", PreviewBytes), strings.Repeat("x", PreviewBytes)},
		{"one byte over", strings.Repeat("x", PreviewBytes+1), strings.Repeat("x", PreviewBytes) + "..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fromString := Preview(tc.input)
			fromBytes := Preview([]byte(tc.input))

			assert.Equal(t, tc.want, fromString)
			assert.Equal(t, tc.want, fromBytes)
		})
	}
}
