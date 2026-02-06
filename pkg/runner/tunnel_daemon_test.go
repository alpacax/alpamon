package runner

import "testing"

func TestValidateTargetAddr(t *testing.T) {
	tests := []struct {
		name       string
		targetAddr string
		want       bool
	}{
		{name: "allow localhost ip", targetAddr: "127.0.0.1:8080", want: true},
		{name: "allow localhost hostname", targetAddr: "localhost:3000", want: true},
		{name: "reject all interfaces", targetAddr: "0.0.0.0:80", want: false},
		{name: "reject private network ip", targetAddr: "192.168.0.10:22", want: false},
		{name: "reject external hostname", targetAddr: "example.com:443", want: false},
		{name: "reject empty string", targetAddr: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateTargetAddr(tc.targetAddr)
			if got != tc.want {
				t.Fatalf("validateTargetAddr(%q) = %v, want %v", tc.targetAddr, got, tc.want)
			}
		})
	}
}
