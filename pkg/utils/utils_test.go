package utils

import (
	"math"
	"testing"
)

func TestConvertGroupIds(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []uint32
	}{
		{
			name:     "valid group IDs",
			input:    []string{"1000", "1001", "1002"},
			expected: []uint32{1000, 1001, 1002},
		},
		{
			name:     "zero is valid",
			input:    []string{"0"},
			expected: []uint32{0},
		},
		{
			name:     "max uint32 is valid",
			input:    []string{"4294967295"},
			expected: []uint32{math.MaxUint32},
		},
		{
			name:     "skip non-numeric strings",
			input:    []string{"1000", "abc", "1002"},
			expected: []uint32{1000, 1002},
		},
		{
			name:     "skip negative values",
			input:    []string{"1000", "-1", "1002"},
			expected: []uint32{1000, 1002},
		},
		{
			name:     "skip overflow values",
			input:    []string{"1000", "4294967296", "1002"},
			expected: []uint32{1000, 1002},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "all invalid",
			input:    []string{"abc", "-1", "99999999999"},
			expected: nil,
		},
		{
			name:     "empty string skipped",
			input:    []string{"", "1000"},
			expected: []uint32{1000},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ConvertGroupIds(tc.input)
			if len(got) != len(tc.expected) {
				t.Fatalf("ConvertGroupIds(%v) returned %v (len %d), want %v (len %d)",
					tc.input, got, len(got), tc.expected, len(tc.expected))
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("ConvertGroupIds(%v)[%d] = %d, want %d",
						tc.input, i, got[i], tc.expected[i])
				}
			}
		})
	}
}
