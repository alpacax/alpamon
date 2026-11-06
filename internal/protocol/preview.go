package protocol

// PreviewBytes bounds how much of a raw message, or of an error quoting one, a log line carries.
const PreviewBytes = 200

// Preview returns the first PreviewBytes of s, with "..." when it cut. It slices before
// converting, so a large frame is never copied whole into a log line.
func Preview[T ~string | ~[]byte](s T) string {
	if len(s) <= PreviewBytes {
		return string(s)
	}
	return string(s[:PreviewBytes]) + "..."
}
