package file

import (
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"sync"
)

const multipartCopyBufSize = 64 << 10 // 64 KiB — goroutine-side copy buffer (pool-reused)
const multipartPipeBufSize = 4 << 20  // 4 MiB — bufio flush granularity; each Flush() → one pipe.Write(4MiB)
const multipartReadBufSize = 4 << 20  // 4 MiB — WriteTo read buffer; matches pipe flush so each Read returns 4MiB

const (
	multipartFieldContent = "content"
	multipartFieldName    = "name"
)

// multipartCopyPool reuses 64 KiB buffers for the goroutine-side io.CopyBuffer.
var multipartCopyPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartCopyBufSize)
		return &b
	},
}

// multipartReadPool reuses 4 MiB buffers for WriteTo on the reader side.
// Large buffers ensure each pr.Read returns a full 4 MiB pipe-write chunk,
// so net/http's chunkedWriter.Write is called ceil(size/4MiB) times instead
// of ceil(size/32KiB), collapsing allocs/op from ~3200 to ~25 for 100 MB.
var multipartReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartReadBufSize)
		return &b
	},
}

// multipartPipeWriterPool reuses 4 MiB-buffered bufio.Writers for the
// large-path producer goroutine. Without this, every concurrent upload would
// allocate a fresh 4 MiB buffer (bufio.NewWriterSize), and concurrent
// streaming uploads would still grow RSS by +4 MiB each.
var multipartPipeWriterPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(io.Discard, multipartPipeBufSize)
	},
}

// multipartReader wraps a *io.PipeReader and implements io.WriterTo.
// When net/http detects WriterTo it calls WriteTo instead of looping small
// Reads through a 32 KiB buffer, so chunkedWriter.Write is called far fewer
// times.
type multipartReader struct {
	*io.PipeReader
}

func (r multipartReader) WriteTo(dst io.Writer) (int64, error) {
	bufPtr := multipartReadPool.Get().(*[]byte)
	defer multipartReadPool.Put(bufPtr)
	return io.CopyBuffer(dst, r.PipeReader, *bufPtr)
}

// countingWriter discards bytes and counts them. Used to measure the multipart
// envelope size without holding any of it in memory.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// multipartEnvelopeSize returns the byte count of the multipart envelope
// (boundary frames + headers + closer) excluding the file body, by replaying
// the same writer operations against a counting writer with an empty body.
//
// Why this works: total_wire = envelope + bodyN. mime/multipart writes part
// headers (sorted deterministically since Go 1.17) and boundary frames
// independently of the body content, so the envelope size for given
// (boundary, fileName, isRecursive) is fixed. Adding bodyN bytes to the empty
// measurement yields the exact Content-Length.
func multipartEnvelopeSize(boundary, fileName string, isRecursive bool) (int64, error) {
	var c countingWriter
	mw := multipart.NewWriter(&c)
	if err := mw.SetBoundary(boundary); err != nil {
		return 0, err
	}
	if _, err := mw.CreateFormFile(multipartFieldContent, fileName); err != nil {
		return 0, err
	}
	if isRecursive {
		if err := mw.WriteField(multipartFieldName, fileName); err != nil {
			return 0, err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}
	return c.n, nil
}

// buildMultipartStream returns a streaming multipart body containing `src`
// under form field "content". The caller MUST Close the returned reader. The
// producer goroutine owns src.Close() and propagates a non-nil close error
// (e.g., a non-zero `cat` exit from cmdReadCloser) to the reader via
// pw.CloseWithError, so demoted-read failures surface as upload errors
// instead of silent empty/truncated payloads.
//
// hint is the source size in bytes. Pass -1 when unknown. Sources smaller
// than multipartPipeBufSize (4 MiB) skip the bufio + 4 MiB pool buffer and
// use Go's default 32 KiB copy buffer, since payloads that fit in one flush
// don't benefit from the larger pool buffer.
//
// The third return value is the exact HTTP Content-Length to send (envelope
// + body) for the small path when hint is known, allowing the transport to
// use identity TE and skip the chunk-header overhead that dominates KB-MB
// uploads. For the large path it is always -1 (chunked TE): net/http wraps
// finite-length bodies in io.LimitReader, which loses the multipartReader
// WriterTo bypass and forces 32 KiB reads from the pipe — at 4 MiB pipe
// flushes that yields ~125x more reads per flush, costing far more than
// the chunk-header bytes save.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool, hint int64) (io.ReadCloser, string, int64, error) {
	if hint >= 0 && hint < multipartPipeBufSize {
		return buildMultipartStreamSmall(src, fileName, isRecursive, hint)
	}
	return buildMultipartStreamLarge(src, fileName, isRecursive)
}

// buildMultipartStreamSmall handles sources smaller than multipartPipeBufSize
// (4 MiB) using Go's default 32 KiB copy buffer and no pool allocation —
// avoids 4 MiB over-provisioning for payloads that fit in one flush.
func buildMultipartStreamSmall(src io.ReadCloser, fileName string, isRecursive bool, hint int64) (io.ReadCloser, string, int64, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	contentLength := int64(-1)
	if hint >= 0 {
		env, err := multipartEnvelopeSize(mw.Boundary(), fileName, isRecursive)
		if err != nil {
			_ = src.Close()
			_ = pw.Close()
			return nil, "", 0, err
		}
		contentLength = env + hint
	}

	go func() {
		var pipeErr error

		// LIFO defer order: panic-recover → src.Close (latches close err) →
		// pipe-close (uses accumulated pipeErr).
		defer func() {
			if pipeErr != nil {
				_ = pw.CloseWithError(pipeErr)
			} else {
				_ = pw.Close()
			}
		}()
		defer func() {
			if cerr := src.Close(); cerr != nil && pipeErr == nil {
				pipeErr = cerr
			}
		}()
		defer func() {
			if rec := recover(); rec != nil {
				pipeErr = fmt.Errorf("multipart panic: %v", rec)
			}
		}()

		failPipe := func(err error) bool {
			if err != nil && pipeErr == nil {
				pipeErr = err
			}
			return err != nil
		}

		fw, err := mw.CreateFormFile(multipartFieldContent, fileName)
		if failPipe(err) {
			return
		}
		if failPipe(func() error { _, err := io.Copy(fw, src); return err }()) {
			return
		}
		if isRecursive {
			if failPipe(mw.WriteField(multipartFieldName, fileName)) {
				return
			}
		}
		if failPipe(mw.Close()) {
			return
		}
	}()

	return pr, contentType, contentLength, nil
}

// buildMultipartStreamLarge handles sources >= multipartPipeBufSize (4 MiB)
// or of unknown size. All three multi-MiB allocations are pool-reused so RSS
// does not grow with concurrent uploads:
//   - bufio.Writer (4 MiB pipe-flush buffer) via multipartPipeWriterPool
//   - copy buffer (64 KiB) via multipartCopyPool
//   - reader-side WriteTo buffer (4 MiB) via multipartReadPool
//
// Always returns contentLength=-1 (chunked TE). See buildMultipartStream for
// the rationale: setting a finite ContentLength on the request makes net/http
// wrap the body in io.LimitReader, which strips multipartReader's WriterTo
// and forces 32 KiB reads — far slower than the 4 MiB chunk-header overhead
// it would save.
func buildMultipartStreamLarge(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, int64, error) {
	pr, pw := io.Pipe()
	bufW := multipartPipeWriterPool.Get().(*bufio.Writer)
	bufW.Reset(pw)
	mw := multipart.NewWriter(bufW)
	contentType := mw.FormDataContentType()

	go func() {
		bufPtr := multipartCopyPool.Get().(*[]byte)
		var pipeErr error

		// LIFO defer order: panic-recover → src.Close (latches close err) →
		// pool puts → pipe-close. Body panics surface via recover; src.Close
		// errors surface only if no earlier failure already set pipeErr.
		// bufW is reset to io.Discard before being returned to the pool so it
		// does not retain a reference to pw after we hand it back.
		defer func() {
			if pipeErr != nil {
				_ = pw.CloseWithError(pipeErr)
			} else {
				_ = pw.Close()
			}
		}()
		defer func() {
			bufW.Reset(io.Discard)
			multipartPipeWriterPool.Put(bufW)
		}()
		defer multipartCopyPool.Put(bufPtr)
		defer func() {
			if cerr := src.Close(); cerr != nil && pipeErr == nil {
				pipeErr = cerr
			}
		}()
		defer func() {
			if rec := recover(); rec != nil {
				pipeErr = fmt.Errorf("multipart panic: %v", rec)
			}
		}()

		failPipe := func(err error) bool {
			if err != nil && pipeErr == nil {
				pipeErr = err
			}
			return err != nil
		}

		fw, err := mw.CreateFormFile(multipartFieldContent, fileName)
		if failPipe(err) {
			return
		}
		_, err = io.CopyBuffer(fw, src, *bufPtr)
		if failPipe(err) {
			return
		}
		if isRecursive {
			if failPipe(mw.WriteField(multipartFieldName, fileName)) {
				return
			}
		}
		if failPipe(mw.Close()) {
			return
		}
		if failPipe(bufW.Flush()) {
			return
		}
	}()

	return multipartReader{pr}, contentType, -1, nil
}
