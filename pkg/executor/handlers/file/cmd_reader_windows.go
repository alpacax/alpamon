//go:build windows

package file

// cmdReadCloser is unix-only; this stub keeps the package buildable on
// Windows where readFileAs uses os.Open directly.
