package cloud

import (
	"fmt"
	"io"
)

// readLimitedN reads up to max bytes from r and errors out if the payload
// exceeds the cap. Defends against a misbehaving / spoofed metadata responder
// filling memory with garbage — real IMDS responses are tiny (well under 8 KB).
func readLimitedN(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response exceeds %d bytes", max)
	}
	return body, nil
}
