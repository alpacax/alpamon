package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFormatTimeoutBanner_GivenSubSecondRemainder_WhenFormatted_ThenTruncatesToWholeSeconds(t *testing.T) {
	assert.Equal(t, "Command timed out after 2s", formatTimeoutBanner(2700*time.Millisecond))
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
			name:   "GivenBannerTextFollowedByMoreOutput_WhenStripped_ThenOutputUnchanged",
			output: "before\n\nCommand timed out after 2s\nafter",
			want:   "before\n\nCommand timed out after 2s\nafter",
		},
		{
			name:   "GivenOutputStartingWithBannerText_WhenStripped_ThenOutputUnchanged",
			output: "Command timed out after 2s\nafter",
			want:   "Command timed out after 2s\nafter",
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

func TestAppendTimeoutBanner(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "GivenOutput_WhenAppended_ThenBannerFollowsSeparator",
			output: "some output",
			want:   "some output\n\nCommand timed out after 2s",
		},
		{
			name:   "GivenEmptyOutput_WhenAppended_ThenBannerHasNoLeadingNewlines",
			output: "",
			want:   "Command timed out after 2s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendTimeoutBanner(tt.output, 2*time.Second)

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.output, StripTimeoutBanner(got), "Strip must undo Append")
		})
	}
}
