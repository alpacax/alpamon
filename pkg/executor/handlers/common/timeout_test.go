package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFormatTimeoutBanner_GivenSubSecondRemainder_WhenFormatted_ThenTruncatesToWholeSeconds(t *testing.T) {
	assert.Equal(t, "Command timed out after 2s", FormatTimeoutBanner(2700*time.Millisecond))
}

func TestStripTimeoutBanner(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "GivenOutputFollowedByBanner_WhenStripped_ThenSeparatorAndBannerRemoved",
			output: "some output\n\nCommand timed out after 2s",
			want:   "some output",
		},
		{
			name:   "GivenBannerOnly_WhenStripped_ThenEmptyStringRemains",
			output: "Command timed out after 2s",
			want:   "",
		},
		{
			name:   "GivenOutputWithNoBanner_WhenStripped_ThenOutputUnchanged",
			output: "some output",
			want:   "some output",
		},
		{
			name:   "GivenEmptyString_WhenStripped_ThenEmptyStringRemains",
			output: "",
			want:   "",
		},
		{
			name:   "GivenTwoBanners_WhenStripped_ThenOnlyTheLastOneRemoved",
			output: "Command timed out after 1s\n\nmore output\n\nCommand timed out after 2s",
			want:   "Command timed out after 1s\n\nmore output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, StripTimeoutBanner(tt.output))
		})
	}
}
